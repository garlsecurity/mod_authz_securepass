%global commit 515f59a2731c0b9350a96f2fe4703e5d9e2c8903
%global shortcommit %(c=%{commit}; echo ${c:0:7})

Name: 		mod_authz_securepass
Summary: 	Apache 2.0/2.2 compliant module that supports authorization via SecurePass

Version: 	0.1
Release: 	1

Source0: 	https://github.com/garlsecurity/%{name}/archive/%{commit}/%{name}-%{commit}.tar.gz
Source1:	mod_authz_securepass.conf
URL: 		https://github.com/garlsecurity/mod_authz_securepass

Group: 		System Environment/Daemons
License: 	GPLv2+

BuildRoot: 	%{_tmppath}/%{name}-root
BuildRequires: 	libcurl-devel
BuildRequires: 	httpd-devel

Requires: 	libcurl

%description
mod_authz_securepass is an Apache module that supports authorization via SecurePass.

SecurePass provides identity management and web single sign-on through the CAS protocol.

%prep
%setup -qn %{name}-%{commit}

%build
make 

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/httpd/modules/
mkdir -p $RPM_BUILD_ROOT/etc/httpd/conf.d/

install -m 755 build/.libs/mod_authz_securepass.so $RPM_BUILD_ROOT/%{_libdir}/httpd/modules/

install %{SOURCE1} $RPM_BUILD_ROOT/etc/httpd/conf.d/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT


%post
%service -q httpd restart

%postun
if [ "$1" = "0" ]; then
%service -q httpd restart
fi


%files
%defattr(-,root,root,-)
%doc LICENSE INSTALL README.md
%{_libdir}/httpd/modules/*.so
%config(noreplace) /etc/httpd/conf.d/*.conf

%changelog
* Fri Nov 7 2014 Giuseppe Paterno' (gpaterno@garl.ch)
- First RPM of the SecurePass Apache authrization module
