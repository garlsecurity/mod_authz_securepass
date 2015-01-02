/*
 *  
 * Authors: Alessandro Lorenzi <alorenzi@alorenzi.eu>
 *			gplll <gplll1818@gmail.com>
 *  
 */

#include "apr_lib.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"	/* for ap_hook_(check_user_id | auth_checker)*/
#include "util_md5.h"

#include "curl/curl.h"
#include "jsmn.h"

#define AUTHZ_GRANTED 1
#define AUTHZ_DENIED 0
#define DEFAULT_GROUP_TMO 600
#define DEFAULT_CACHE_CLEAN_ITV 1800
#define ERR_LINE_LEN 80
#define CACHE_LINE_LEN 80
#define CURL_BUF_LEN 4096 /* this size is exaggereted...but it's for free */
#define JSON_MAX_TOKENS 200 /* this size is exaggereted...but it's for free */
#define APP_ID "X-SecurePass-App-ID"
#define APP_SECRET "X-SecurePass-App-Secret"
#define ACCEPT "Accept: application/json"
#define RC_STRING "rc"
#define RC_STRING_LEN 2
#define RC_RESULT_OK "0"
#define RC_RESULT_OK_LEN 1 
#define MEMBER_STRING "member"
#define MEMBER_STRING_LEN 6
#define MEMBER_RESULT_TRUE "true"
#define MEMBER_RESULT_TRUE_LEN 4
#define MYDEBUG 1 /* set to 1 to enable pieces of code useful only during development/maintenance of this module */

/*
 * Structure for the module itself.  The definition of this structure
 * is at the end of the file.
 */
module AP_MODULE_DECLARE_DATA authz_securepass_module;

typedef enum {
	cmd_sp_debug, cmd_sp_check_group, cmd_sp_api, cmd_sp_appid, cmd_sp_app_secret, 
	cmd_sp_cache_path, cmd_sp_group_tmo, cmd_sp_clean_itv 
} valid_cmds;

/* Structure for server config */
typedef struct {
	int debug;
	int check_group;
	char *REST_url;
	char *app_id;
	char *app_secret;
	char *cache_path;
	int cache_group_tmo;
	int cache_clean_itv;
} sp_cfg;

/*
 *  Data type for per-directory configuration
 */
typedef struct
{
	int enabled;
	int authoritative;
	char *forced_user; /* only used to simulate CAS user during module development */
	char *forced_group; /* only used to simulate a successful user-group mapping during module development */
} authz_securepass_dir_config_rec;

typedef struct { 
	char *fullpath; /* full pathname into filesystem */
	char *name; 	/* unique name used to generate MD5 filename */ 
} sp_cache_file;

struct sp_curl_buf {
	char buf[CURL_BUF_LEN];
	size_t size;
};

static size_t
curl_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct sp_curl_buf *cbuf = (struct sp_curl_buf *)userp;
 
	if((nmemb*size) + cbuf->size >= CURL_BUF_LEN)
	/* response is larger than allocated buffer - return KO */
		return 0;

	/* copy received bytes into buffer */
	memcpy((cbuf->buf + cbuf->size), contents, (nmemb*size));
	cbuf->size += (nmemb*size);

	/* return OK */
	return (nmemb*size);
}

static int get_from_URL (request_rec *r, const char *group)
{
	CURLcode res;
	CURL *curl_handle;
	struct curl_slist *slist=NULL;
	struct sp_curl_buf cbuf;
	jsmn_parser p;
	jsmntok_t tokens[JSON_MAX_TOKENS];
	int n, i, l;
	char *s;
	int rc = 0;
	int is_member = 0;

	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);

	if (c->debug) 
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: entering get_from_URL()");
 
	/* always initialize curl library, as we don't know if some other module has called curl's in the meantime */
	curl_global_init(CURL_GLOBAL_ALL);

	curl_handle = curl_easy_init();
	if (!curl_handle) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		"SecurePass curl_easy_init failed");
		return 0;
	}
	/* setup the request (URL, callback func, memory buffer, user agent) */
	curl_easy_setopt(curl_handle, CURLOPT_URL, c->REST_url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_callback);
	cbuf.size = 0;
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&cbuf);
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "mod_authz_securepass");

	/* set SSL options - for now, don't validate server */
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);

	/* add HTTP headers */
	slist = curl_slist_append(slist, (s=apr_psprintf(r->pool, "%s:%s", APP_ID, c->app_id)));
	if (c->debug) 
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: AppID=%s", s);
	slist = curl_slist_append(slist, apr_psprintf(r->pool, "%s:%s", APP_SECRET, c->app_secret));
	slist = curl_slist_append(slist, ACCEPT);

	curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, slist);

	/* attach POST data */
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, 
		(s=apr_psprintf(r->pool,"USERNAME=%s&GROUP=%s",r->user,group)));

	/* Send the request */
	res = curl_easy_perform(curl_handle);
	if (res != CURLE_OK) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"SecurePass curl_easy_perform() failed %s", curl_easy_strerror(res));
		curl_easy_cleanup(curl_handle);
		return 0;
	}
	if (c->debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"SecurePass curl_easy_perform() retrieved %lu bytes: %s", (long)cbuf.size, cbuf.buf);

	/* free resources allocated by curl */
	curl_slist_free_all(slist);
	curl_easy_cleanup(curl_handle);
	curl_global_cleanup();

	/* Parse response to get JSON object */
	jsmn_init(&p);
	n = jsmn_parse(&p, cbuf.buf, cbuf.size, tokens, JSON_MAX_TOKENS);
	if (c->debug) 
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: found %d JSON tokens", n);
	for (i = 0; i < n; i++) {
		l = tokens[i].end-tokens[i].start;
#if 0
		// enable this code only if you're really desperate with JSON parsing
		if (c->debug) {
			s = apr_pcalloc(r->pool, l+1);
			memcpy(s, (cbuf.buf + tokens[i].start), l);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
				"SecurePass: Found JSON token: type=%s, value=%s",
				json_types[tokens[i].type], s);
		}
#endif
		/* Look for a field like:  "rc": 0 */
		if ((tokens[i].type == JSMN_STRING) && (l == RC_STRING_LEN) && 
			(!memcmp(cbuf.buf + tokens[i].start, RC_STRING, l))) {
			i++;
			if (i == n) 
				break;
			l = tokens[i].end-tokens[i].start;
			if ((tokens[i].type == JSMN_PRIMITIVE) && (l == RC_RESULT_OK_LEN) && 
				(!memcmp(cbuf.buf + tokens[i].start, RC_RESULT_OK, l))) {
				rc = 1;
			}
			if (c->debug) 
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: got RC=%s from RESTful API", 
					((rc) ? "OK" : "KO"));
			continue;
		}
		/* Look for a field like:  "member": true */
		if ((tokens[i].type == JSMN_STRING) && (l == MEMBER_STRING_LEN) && 
			(!memcmp(cbuf.buf + tokens[i].start, MEMBER_STRING, MEMBER_STRING_LEN))) {
			i++;
			if (i == n) 
				break;
			l = tokens[i].end-tokens[i].start;
			if ((tokens[i].type == JSMN_PRIMITIVE) && (l == MEMBER_RESULT_TRUE_LEN) && 
				(!memcmp(cbuf.buf + tokens[i].start, MEMBER_RESULT_TRUE, l))) {
					is_member = 1;
			}
			if (c->debug) 
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: got member=%s from RESTful API", 
					((is_member) ? "true" : "false"));
			continue;
		}
	}
	if (rc && is_member)
		return 1;
	else
		return 0;
}


static void clean_cache(request_rec *r, sp_cfg *c)
{
	apr_time_t last_clean;
	apr_off_t begin = 0;
	char *path;
	apr_file_t *lf, *cf;
	apr_status_t i;
	apr_dir_t *d;
	char line[ERR_LINE_LEN];
	apr_finfo_t finfo;
	int file_is_new = 0;

	if (c->debug) 
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: entering clean_cache()");
	path = apr_psprintf(r->pool, "%s.lastclean", c->cache_path);

	/* Open .lastclean file, holding time of last clean */
	if(apr_file_open(&lf, path, APR_FOPEN_READ|APR_FOPEN_WRITE, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool) 
		!= APR_SUCCESS) {

		/* file does not exist or cannot be opened - create it */
		if (c->debug) 
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
				"SecurePass: .lastclean file %s doesn't exist...creating it", path);
		if((i = apr_file_open(&lf, path, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), 
			(APR_FPROT_UREAD|APR_FPROT_UWRITE), r->pool)) != APR_SUCCESS) {

			apr_strerror(i, line, ERR_LINE_LEN);
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "SecurePass: Could not create cache .lastclean file '%s': %s", path, line);
			return;
		}
		file_is_new = 1;
	}
	apr_file_lock(lf, APR_FLOCK_EXCLUSIVE);
	apr_file_seek(lf, APR_SET, &begin);

	if (!file_is_new) {
		/* check if it is time to clean the cache */
		apr_file_gets(line, ERR_LINE_LEN, lf);
		if(sscanf(line, "%" APR_TIME_T_FMT, &last_clean) != 1) { /* corrupt file */
			apr_file_unlock(lf);
			apr_file_close(lf);
			apr_file_remove(path, r->pool);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "SecurePass: Cache .lastclean file has been found corrupted and has been removed");
			return;
		}
		if(last_clean > (apr_time_now()-(c->cache_clean_itv*((apr_time_t) APR_USEC_PER_SEC)))) { 
			/* not enough time has elapsed */
			/* release the locks and file descriptors that we no longer need */
			apr_file_unlock(lf);
			apr_file_close(lf);
			if(c->debug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
				"SecurePass: Cache not cleaned as not enough time has elapsed");
			return;
		}
		apr_file_seek(lf, APR_SET, &begin);
		apr_file_trunc(lf, begin);
	}
	if(c->debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: Beginning cache clean");
	apr_file_printf(lf, "%" APR_TIME_T_FMT "\n", apr_time_now());
	apr_file_unlock(lf);
	apr_file_close(lf);

	/* read all the files in the directory */
	if(apr_dir_open(&d, c->cache_path, r->pool) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
			"SecurePass: Error opening cache directory '%s' for cleaning", c->cache_path);
		return;
	}
	do {
		i = apr_dir_read(&finfo, APR_FINFO_NAME, d);
		if(i == APR_SUCCESS) {
			if(finfo.name[0] == '.') /* skip hidden files and parent directories */
				continue;
			path = apr_psprintf(r->pool, "%s%s", c->cache_path, finfo.name);
			if(c->debug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: Processing cache file '%s'", finfo.name);

			/* open file */
			if(apr_file_open(&cf, path, APR_FOPEN_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "SecurePass: Unable to clean cache file '%s'", path);
				continue;
			}

			/* look if time has elapsed */
			apr_file_gets(line, ERR_LINE_LEN, cf);
			if(sscanf(line, "%" APR_TIME_T_FMT, &last_clean) != 1) { /* corrupt file */
				apr_file_close(cf);
				apr_file_remove(path, r->pool);
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
					"SecurePass: Cache file %s has been found corrupted and has been removed", path);
				continue;
			}
			if(last_clean > (apr_time_now()-(c->cache_group_tmo*((apr_time_t) APR_USEC_PER_SEC)))) { 
				/* not enough time has elapsed */
				/* release the locks and file descriptors that we no longer need */
				apr_file_close(cf);
				if(c->debug)
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
						"SecurePass: Cache file %s not removed as time isn't expired", path);
				continue;
			}
			else { 
				 /* delete this file since it is no longer valid */
				apr_file_close(cf);
				apr_file_remove(path, r->pool);
				if(c->debug)
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
						"SecurePass: Cache file %s removed as time is expired", path);
			}
		}
	} while (i == APR_SUCCESS);
	apr_dir_close(d);
}

static void build_file_info (request_rec *r, const char *group, sp_cache_file *cfile)
{
	char *rv;

	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);

	/*
	 * to create a unique name into filesystem, we need: URL of RESTful API, user name, group name
	 */
	cfile->name = apr_psprintf(r->pool, "%s-%s-%s", c->REST_url, r->user, group);

	// generate md5 string
	rv = (char *) ap_md5(r->pool, (unsigned char *) cfile->name);

	// build full pathname
	cfile->fullpath = apr_psprintf(r->pool, "%s%s", c->cache_path, rv);
}

static int get_from_cache (request_rec *r, const char *group)
{
	sp_cache_file cfile;
	apr_file_t *f;
	char line[CACHE_LINE_LEN];
	apr_time_t last_clean;
	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);

	if (c->debug) 
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: entering get_from_cache()");

	build_file_info(r, group, &cfile);

	/* Open cache file, holding time of last query to RESTful URL */
	if (apr_file_open(&f, cfile.fullpath, APR_FOPEN_READ|APR_FOPEN_WRITE, APR_OS_DEFAULT, r->pool) 
		!= APR_SUCCESS) {
		/* file does not exist or cannot be opened */
		if (c->debug) 
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: cache file %s for entry %s doesn't exist", 
				cfile.fullpath, cfile.name);
		return 0;
	}
	/* look if time has elapsed */
	apr_file_gets(line, CACHE_LINE_LEN, f);
	if(sscanf(line, "%" APR_TIME_T_FMT, &last_clean) != 1) { /* corrupt file */
		apr_file_close(f);
		apr_file_remove(cfile.fullpath, r->pool);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
			"SecurePass: Cache file %s for entry %s has been found corrupted and has been removed", 
			cfile.fullpath, cfile.name);
		return 0;
	}
	if(last_clean > (apr_time_now()-(c->cache_group_tmo*((apr_time_t) APR_USEC_PER_SEC)))) { 
		/* cache file is still valid */
		apr_file_close(f);
		if(c->debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
				"SecurePass: Cache file %s for entry %s is valid", cfile.fullpath, cfile.name);
		return 1;
	}
	else { 
		/* delete this file since it is no longer valid */
		apr_file_close(f);
		apr_file_remove(cfile.fullpath, r->pool);
		if(c->debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
				"SecurePass: Cache file %s for entry %s removed as cache time is expired", 
				 cfile.fullpath, cfile.name);
		return 0;
	}
}

static void write_to_cache (request_rec *r, const char *group)
{
	char *name, *fullpath;
	char errmsg[80];
	apr_file_t *f;
	apr_status_t i = APR_EGENERAL;
	apr_off_t begin = 0;

	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);

	if (c->debug) 
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: entering write_to_cache; group= %s", group);

	/* First of all, remove expired files, if Cache Clean Interval has passes */
	clean_cache (r, c);

	if (c->cache_group_tmo == 0) {
		if (c->debug) 
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
			"SecurePass: cache file for user %s, group %s, not created as AuthzSecurepassGroupTimeout is set to 0", 
				r->user, group);
		return;
	}

	/* to create a unique name for file, we need: URL of RESTful API, user name, group name */
	name = apr_psprintf(r->pool, "%s-%s-%s", c->REST_url, r->user, group);

	/* build full pathname concatenating directory name and generated MD5 string */
	fullpath = apr_psprintf(r->pool, "%s%s", c->cache_path, (char *) ap_md5(r->pool, (unsigned char *) name));

	//create file
	if((i = apr_file_open(&f, fullpath, APR_FOPEN_CREATE|APR_FOPEN_WRITE|APR_EXCL, 
		APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool)) != APR_SUCCESS) {

			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
				"SecurePass: cache file %s for entry %s could not be created: %s", 
				fullpath, name, apr_strerror(i, errmsg, 80));
			return;
	}
	if (c->debug) 
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: created file %s for cache entry %s", fullpath, name);

	/* write current time */
	apr_file_seek(f, APR_SET, &begin);
	apr_file_trunc(f, begin);
	apr_file_printf(f, "%" APR_TIME_T_FMT "\n", apr_time_now());
	apr_file_close(f);
}


static int check_securepass_realm(request_rec *r, const char *realmlist)
{
	char *user= r->user;
	char *realm,*w;

	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);
	
	// estrapolo il realm dell'utente
	realm=strchr(user,'@');
	realm++;

	/* Loop through list of realms passed in */
	while (*realmlist != '\0') {

		// get next realm from 'Require sprealm ...' line
		w= ap_getword_conf(r->pool, &realmlist);
		if (c->debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: checking realm %s", w);

		//check if equals to user realm
		if (strcmp(realm,w)==0) {
			return 1;
		}
	}
	return 0;
}

static int check_sp_group (request_rec *r, const char *grouplist)
{
	char *w;

	authz_securepass_dir_config_rec *dir= (authz_securepass_dir_config_rec *)
	ap_get_module_config(r->per_dir_config, &authz_securepass_module);
	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);

#if MYDEBUG
	/* this is only for debugging/testing purposes during module development */
	if (c->debug && dir->forced_group) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: setting group %s", dir->forced_group);
		if (!get_from_cache(r, dir->forced_group)) {
			write_to_cache (r, dir->forced_group);
		}
		return (1);
	}
#endif

	/* Loop through list of groups passed in */
	while (*grouplist != '\0') {

		// get all required groups from the request
		w= ap_getword_conf(r->pool, &grouplist);
		if (c->debug)	
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: checking group %s", w);

		/* see if mapping between user and group is cached */
		if (get_from_cache(r,w)) {
			/* User belong to group */
			return(1);
		}

		/* check if user belongs to group querying RESTFul API URL */
		if (get_from_URL(r,w)) {
			/* User belong to group */
			write_to_cache (r, w);
			return(1);
		}
	}
	return 0;
}

/* This is a debug function to dump current directory and vserver config */
static void dump_config (request_rec *r, authz_securepass_dir_config_rec *dir, sp_cfg *c)
{
	/*ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"SecurePass server=%s", r->server->defn_name);*/

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"SecurePass enabled=%d, debug=%d, check_group=%d REST_url=%s, cache_group_tmo=%d", 
		dir->enabled, c->debug, c->check_group, c->REST_url, c->cache_group_tmo);
}

/* Creator per server configuration*/
static void *create_authz_securepass_server_config (apr_pool_t *pool, server_rec *svr)
{
	sp_cfg *c = apr_pcalloc(pool, sizeof(sp_cfg));

	c->check_group = TRUE;
	c->debug = FALSE;
	c->cache_group_tmo = DEFAULT_GROUP_TMO;
	c->REST_url = NULL;
	c->app_id = NULL;
	c->app_secret = NULL;
	c->cache_path = NULL;
	c->cache_clean_itv = DEFAULT_CACHE_CLEAN_ITV;
	return c;
}

static void *merge_authz_securepass_server_config (apr_pool_t *pool, void *BASE, void *ADD)
{
	sp_cfg *c = apr_pcalloc(pool, sizeof(sp_cfg));
	sp_cfg *base = BASE;
	sp_cfg *add = ADD;

	c->check_group =(add->check_group != TRUE ? add->check_group : base->check_group);
	c->debug =(add->debug != FALSE ? add->debug : base->debug);
	c->cache_group_tmo =(add->cache_group_tmo != DEFAULT_GROUP_TMO ? add->cache_group_tmo : base->cache_group_tmo);
	
	if (add->REST_url != NULL) 
		c->REST_url = apr_pstrdup(pool, add->REST_url);
	else
		c->REST_url = apr_pstrdup(pool, base->REST_url);

	if (add->app_id != NULL) 
		c->app_id = apr_pstrdup(pool, add->app_id);
	else
		c->app_id = apr_pstrdup(pool, base->app_id);

	if (add->app_secret != NULL) 
		c->app_secret = apr_pstrdup(pool, add->app_secret);
	else
		c->app_secret = apr_pstrdup(pool, base->app_secret);

	if (add->cache_path != NULL) 
		c->cache_path = apr_pstrdup(pool, add->cache_path);
	else
		c->cache_path = apr_pstrdup(pool, base->cache_path);
		
	c->cache_clean_itv =(add->cache_clean_itv != DEFAULT_CACHE_CLEAN_ITV ? add->cache_clean_itv : base->cache_clean_itv);
	return c;
}


/*
 * Creator for per-dir configurations. This is called via the hook in the
 * module declaration to allocate and initialize the per-directory
 * configuration data structures declared above.
 */

static void *create_authz_securepass_dir_config(apr_pool_t *p, char *d)
{
	authz_securepass_dir_config_rec *dir= (authz_securepass_dir_config_rec *)
	apr_palloc(p, sizeof(authz_securepass_dir_config_rec));

	dir->enabled= 0;
	dir->authoritative= 1;	/* strong by default */
	dir->forced_user = NULL;
	dir->forced_group = NULL;
	
	return dir;
}

static const char *read_sp_param(cmd_parms *cmd, void *cfg, const char *value)
{
		apr_finfo_t f;
		sp_cfg *c = (sp_cfg *) ap_get_module_config(cmd->server->module_config, &authz_securepass_module);

		switch((size_t) cmd->info) {
				case cmd_sp_debug:
						if(apr_strnatcasecmp(value, "On") == 0)
							c->debug = TRUE;
						else if(apr_strnatcasecmp(value, "Off") == 0)
							c->debug = FALSE;
						break;
				case cmd_sp_check_group:
						if(apr_strnatcasecmp(value, "On") == 0)
							c->check_group = TRUE;
						else if(apr_strnatcasecmp(value, "Off") == 0)
							c->check_group = FALSE;
						break;
				case cmd_sp_group_tmo:
						c->cache_group_tmo = atoi(value);
						break;
				case cmd_sp_api:
						c->REST_url = apr_pstrdup(cmd->pool, value);
						break;
				case cmd_sp_appid:
						c->app_id = apr_pstrdup(cmd->pool, value);
						break;
				case cmd_sp_app_secret:
						c->app_secret = apr_pstrdup(cmd->pool, value);
						break;
				case cmd_sp_clean_itv:
						c->cache_clean_itv = atoi(value);
						break;
				case cmd_sp_cache_path:
						if(apr_stat(&f, value, APR_FINFO_TYPE, cmd->temp_pool) != APR_SUCCESS)
							return(apr_psprintf(cmd->pool, 
								"Securepass: Could not find AuthzSecurepassGroupCachePath '%s'", value));

						if(f.filetype != APR_DIR || value[strlen(value)-1] != '/')
							return(apr_psprintf(cmd->pool, 
								"Securepass:: AuthzSecurepassGroupCachePath '%s' is not a directory or does not end in a trailing '/'!", value));

						c->cache_path = apr_pstrdup(cmd->pool, value);
						/* this is just an example in case we want to log passed parameters*/
						/*ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
							"SecurePass: AuthzSecurepassGroupCachePath = %s", c->cache_path);*/
						break;
				default:
						/* should not happen */
						return(apr_psprintf(cmd->pool, "SecurePass: invalid command '%s'", cmd->directive->directive));
		}
		return NULL;
}

/*
 * Config file commands that this module can handle
 */

static const command_rec authz_securepass_cmds[] =
{
	/* Server directives */

	AP_INIT_TAKE1("AuthzSecurepassDebug",
	read_sp_param,
	(void *) cmd_sp_debug,
	 RSRC_CONF,
	"Set to On to enable SecurePass debug"),

	AP_INIT_TAKE1("AuthzSecurepassCheckGroup",
	read_sp_param,
	(void *) cmd_sp_check_group,
	RSRC_CONF,
	"Set to Off to disable checking of group associated to the user"),

	AP_INIT_TAKE1("AuthzSecurepassRESTfulAPI",
	read_sp_param,
	(void *) cmd_sp_api,
	RSRC_CONF,	
	"URL of RESTful API where to check if a user belongs to a group"),

	AP_INIT_TAKE1("AuthzSecurepassAppID",
	read_sp_param,
	(void *) cmd_sp_appid,
	RSRC_CONF,	
	"Value of X-SecurePass-App-ID to be inserted into HTTP header to invoke Securepass RESTful API"),

	AP_INIT_TAKE1("AuthzSecurepassAppSecret",
	read_sp_param,
	(void *) cmd_sp_app_secret,
	RSRC_CONF,	
	"Value of X-SecurePass-App-Secret to be inserted into HTTP header to invoke Securepass RESTful API"),

	AP_INIT_TAKE1("AuthzSecurepassGroupCachePath",
	read_sp_param,
	(void *) cmd_sp_cache_path,
	RSRC_CONF,	
	"The file system directory where mappings betweeen users and Securepass groups are cached"),

	AP_INIT_TAKE1("AuthzSecurepassGroupTimeout",
	read_sp_param,
	(void *) cmd_sp_group_tmo,
	RSRC_CONF,	
	"Define the timeout of cached group for each user"),

	AP_INIT_TAKE1("AuthzSecurepassCacheCleanInterval",
	read_sp_param,
	(void *) cmd_sp_clean_itv,
	RSRC_CONF,	
	"The minimum amount of time that must pass inbetween cache cleanings"),

	/* Directory directives */

	AP_INIT_FLAG("AuthzSecurepass",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authz_securepass_dir_config_rec, enabled),
	OR_AUTHCFG,
	"Set to 'on' to enable SecurePass module"),

	AP_INIT_FLAG("AuthzSecurepassAuthoritative",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authz_securepass_dir_config_rec, authoritative),
	OR_AUTHCFG,
	"Set to 'off' to allow access control to be passed along to lower "
		"modules if this module can't confirm access rights" ),

	AP_INIT_TAKE1("AuthzSecurepassForceUser",
	ap_set_string_slot,
	(void *)APR_OFFSETOF(authz_securepass_dir_config_rec, forced_user),
	OR_AUTHCFG,	
	"only used during module development to simulate CAS user"),

	AP_INIT_TAKE1("AuthzSecurepassForceGroup",
	ap_set_string_slot,
	(void *)APR_OFFSETOF(authz_securepass_dir_config_rec, forced_group),
	OR_AUTHCFG,	
	"only used during module development to simulate a succesful mapping between user and group"),

	{ NULL }
};

#if (AP_SERVER_MINORVERSION_NUMBER == 4)
static const char *sp_parse_config(cmd_parms *cmd, const char *require_line,
									 const void **parsed_require_line) {
	const char *expr_err = NULL;
	ap_expr_info_t *expr;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server, 
			"SecurePass: entering sp_parse_config(), require_line=%s", require_line);
	expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT, &expr_err, NULL);
	if (expr_err)
		return (apr_pstrcat(cmd->temp_pool, "Cannot parse expression in require line: ", expr_err, NULL));
	*parsed_require_line = expr;
	return NULL;
}

static authz_status sprealm_check_authorization(request_rec *r,
												 const char *require_args,
												 const void *parsed_require_args) {

	authz_securepass_dir_config_rec *dir= (authz_securepass_dir_config_rec *) 
				ap_get_module_config(r->per_dir_config, &authz_securepass_module);
	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);

	const char *err = NULL;
	const ap_expr_info_t *expr = parsed_require_args;
	const char *require;

#if MYDEBUG
	/* this is only used during module development to simulate CAS user */
	if (dir->forced_user) {
		r->user = apr_pcalloc(r->pool, 100);
		strcpy (r->user, dir->forced_user);
	}
#endif

	if (c->debug) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass checking user %s, required_sprealms=%s", 
				r->user, require_args);
		dump_config (r, dir, c);
	}
	if (!r->user) {
		return AUTHZ_DENIED_NO_USER;
	}
	require = ap_expr_str_exec(r, expr, &err);
	if (err) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "SecurePass: Can't evaluate expression: %s", err);
		return AUTHZ_DENIED;
	}
	if (c->debug) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: require=%s", require);
	}
	if (check_securepass_realm (r, require)) {
		/* a Realm has been found */
		return AUTHZ_GRANTED;
	} else {
		return AUTHZ_DENIED;
	}
}

static authz_status spgroup_check_authorization(request_rec *r,
												 const char *require_args,
												 const void *parsed_require_args) {

	authz_securepass_dir_config_rec *dir= (authz_securepass_dir_config_rec *) 
				ap_get_module_config(r->per_dir_config, &authz_securepass_module);
	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);

	const char *err = NULL;
	const ap_expr_info_t *expr = parsed_require_args;
	const char *require;

#if MYDEBUG
	/* this is only used during module development to simulate CAS user */
	if (dir->forced_user) {
		r->user = apr_pcalloc(r->pool, 100);
		strcpy (r->user, dir->forced_user);
	}
#endif

	if (c->debug) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass checking user %s, required_spgroups=%s", 
				r->user, require_args);
	}
	if (!r->user) {
		return AUTHZ_DENIED_NO_USER;
	}
	require = ap_expr_str_exec(r, expr, &err);
	if (err) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "SecurePass: Can't evaluate expression: %s", err);
		return AUTHZ_DENIED;
	}
	if (c->debug) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass: require=%s", require);
	}
	if (check_sp_group (r, require)) {
		return AUTHZ_GRANTED;
	} else {
		return AUTHZ_DENIED;
	}

}

#else // (AP_SERVER_MINORVERSION_NUMBER == 4)

static int authz_securepass_check_user_access(request_rec *r) 
{
	authz_securepass_dir_config_rec *dir= (authz_securepass_dir_config_rec *)
	ap_get_module_config(r->per_dir_config, &authz_securepass_module);

	sp_cfg *c = (sp_cfg *) ap_get_module_config(r->server->module_config, &authz_securepass_module);

	int m= r->method_number;
	register int x;
	const char *t, *w;
	const apr_array_header_t *reqs_arr= ap_requires(r);
	require_line *reqs;
	int realm_requested = 0;
	int group_requested = 0;
	int realm_found = 0;
	int group_found = 0;

#if MYDEBUG
	/* this is only used during module development to simulate CAS user */
	if (dir->forced_user) {
		r->user = apr_pcalloc(r->pool, 100);
		strcpy (r->user, dir->forced_user);
	}
#endif

	if (c->debug) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "SecurePass checking user %s", r->user);
		dump_config (r, dir, c);
	}

	/* If not enabled, pass */
	if ( !dir->enabled ) return DECLINED;

	/* If there are no Require arguments, pass */
	if (!reqs_arr) return DECLINED;
	reqs= (require_line *)reqs_arr->elts;

	/* Loop through the "Require" argument list */
	for(x= 0; x < reqs_arr->nelts; x++) {
		if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) continue;

		t= reqs[x].requirement;
		w= ap_getword_white(r->pool, &t);

		/* Check if user belongs to required realm */
		if ( !strcasecmp(w, "sprealm") && !realm_found) {
			realm_requested = 1;
			if (check_securepass_realm(r,t)){
				/* a Realm has been found - don't check for more lines sprealm, in case they exist */
				realm_found=1;
			}
		}
		/* Check if user belongs to required group */
		if ((c->check_group) && (!strcasecmp(w, "spgroup")) && (!group_found)) {
			group_requested = 1;
			if (check_sp_group(r,t)) {
				/* User belongs to required group - don't check for more lines spgroup, in case they exist */
				group_found=1;
			}
		}
	}
	if (c->debug) {
		if (realm_requested) 
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"SecurePass user %s is %sin realm list", r->user, ((realm_found) ? "":"NOT "));
		if (group_requested) 
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"SecurePass user %s is %sin required group", r->user, ((group_found) ? "":"NOT "));	
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			 "SecurePass realm_requested=%u realm_found= %u group_requested=%u group_found=%u", 
				realm_requested, realm_found, group_requested, group_found);
	}
	if ((!realm_requested||realm_found) && (!group_requested||group_found)) {
		return OK;
	}
	
	/* If we aren't authoritive, decline */
	if (!dir->authoritative)
		return DECLINED;
	/* Authentication failed and we are authoritive, declare unauthorized */
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "access to %s failed, reason: user %s not allowed access", r->uri, r->user);
	ap_note_basic_auth_failure(r);
	return HTTP_UNAUTHORIZED;
}
#endif

static int authz_sp_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s)
{
	int status = OK;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "SecurePass entering authz_sp_post_config()");
	while (s != NULL && status == OK) {	
		sp_cfg *c = (sp_cfg *) ap_get_module_config(s->module_config, &authz_securepass_module);
		if (c->debug) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "SecurePass: server->defn_name=%s", s->defn_name);
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "SecurePass: c->REST_url=%s", c->REST_url);
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "SecurePass: c->cache_path=%s", c->cache_path);
		}
		if (c->REST_url == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, 
				"SecurePass: directive AuthzSecurepassRESTfulAPI is not configured!");
			status =  HTTP_INTERNAL_SERVER_ERROR;
		}
		if (c->app_id == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, 
				"SecurePass: directive AuthzSecurepassAppID is not configured!");
			status =  HTTP_INTERNAL_SERVER_ERROR;
		}
		if (c->app_secret == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, 
				"SecurePass: directive AuthzSecurepassAppSecret is not configured!");
			status =  HTTP_INTERNAL_SERVER_ERROR;
		}
		if (c->cache_path == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, 
				"SecurePass: directive AuthzSecurepassGroupCachePath is not configured!");
			status =  HTTP_INTERNAL_SERVER_ERROR;
		}
		s = s->next;
	}
	return status;
}

#if (AP_SERVER_MINORVERSION_NUMBER == 4)
static const authz_provider authz_sprealm_provider =
{
	&sprealm_check_authorization,
	&sp_parse_config,
};

static const authz_provider authz_spgroup_provider =
{
	&spgroup_check_authorization,
	&sp_parse_config,
};
#endif

static void authz_securepass_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(authz_sp_post_config, NULL, NULL, APR_HOOK_LAST);
#if (AP_SERVER_MINORVERSION_NUMBER == 4)
	/* Register authz providers */
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "sprealm",
							AUTHZ_PROVIDER_VERSION,
							&authz_sprealm_provider,
							AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "spgroup",
							AUTHZ_PROVIDER_VERSION,
							&authz_spgroup_provider,
							AP_AUTH_INTERNAL_PER_CONF);
#else
	ap_hook_auth_checker(authz_securepass_check_user_access, NULL, NULL,
		APR_HOOK_MIDDLE);
#endif
}

module AP_MODULE_DECLARE_DATA authz_securepass_module = {
	STANDARD20_MODULE_STUFF,
	create_authz_securepass_dir_config,	 	/* create per-dir config */
	NULL,								 	/* merge per-dir config */
	create_authz_securepass_server_config,	/* create per-server config */
	merge_authz_securepass_server_config,	/* merge per-server config */
	authz_securepass_cmds,					/* command apr_table_t */
	authz_securepass_register_hooks			/* register hooks */
};
