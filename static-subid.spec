Name:		static-subid
Version:	0.1.0
Release:	1%{?dist}

# Only the test_framework is CC-PDDC
License:	BSD-3-Clause and CC-PDDC

URL:		https://github.com/fermitools/%{name}
Source0:	%{url}/archive/refs/tags/%{version}.tar.gz

BuildRequires:  redhat-rpm-config systemd-rpm-macros
BuildRequires:  cmake >= 3.21
BuildRequires:	coreutils git
BuildRequires:	gcc
BuildRequires: (rubygem-asciidoctor or asciidoc )


Suggests:	%{name}-systemd
Requires:	shadow-utils
Summary:	Assign deterministic subordinate UID/GID ranges
%description
static-subid is a small utility to generate predictable subordinate UID and GID ranges for Linux users, avoiding the default dynamic allocation behavior used by many systems.

This can be useful when you need consistent UID/GID mappings across multiple systems (for example in identity-mapped rootless containers or reproducible user namespace setups).

Subordinate IDs are used by user namespaces to map container UIDs/GIDs back to host IDs. By making selections deterministic, you avoid unpredictable or overlapping ranges between hosts.

%package systemd
Requires:       %{name} = %{version}-%{release}
Requires:       systemd
Summary:        Systemd integration for static-subid
BuildArch:	noarch
%description systemd
Provides a systemd service to generate subids for a username

%package systemd-user-permit
Requires:       %{name}-systemd = %{version}-%{release}
Requires:	systemd
Summary:	Systemd user integration for static-subid
BuildArch:	noarch
%description systemd-user-permit
Provides a set of user-scoped systemd services that automatically allow a non-root user to ensure their own subid ranges are correctly configured.


%prep
%autosetup

%build
%cmake -Wdev -Wdeprecated --warn-uninitialized  \
       -DVERSION=%{version} \
       -DBUILD_TESTING=ON   \
       -DCMAKE_INSTALL_SYSTEMD_UNITDIR=%{_unitdir} \
       -DCMAKE_INSTALL_SYSTEMD_USERUNITDIR=%{_userunitdir} \
       -DCMAKE_INSTALL_POLKIT_RULESDIR=%{_datarootdir}/polkit-1/rules.d
%cmake_build

%install
%cmake_install

%check
%ctest


%files
%defattr(0644,root,root,0755)
%license LICENSE
%doc %{_mandir}
%config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%ghost %dir %{_sysconfdir}/%{name}/%{name}.conf.d
%attr(0755,root,root) %{_libexecdir}/*

%files systemd
%doc docs/README.systemd
%{_unitdir}/static-subid@.service

%files systemd-user-permit
%doc docs/README.systemd
%{_userunitdir}/setup-static-subid.service
%{_datarootdir}/polkit-1/rules.d/50-static-subid.rules


%changelog
* Mon Feb 16 2026 Pat Riehecky <riehecky@fnal.gov> - 0.1.0
- Initial release
