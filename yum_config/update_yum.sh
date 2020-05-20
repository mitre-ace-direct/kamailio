#sudo yum clean all
#sudo cp yum.conf /etc/yum.conf
#sudo rm -rf /etc/yum.repos.d
#sudo cp -rf yum.repos.d/* /etc/yum.repos.d
#sudo cp -f RPM* /etc/pki/rpm-gpg
#sudo rm -rf /var/cache/yum
sudo cp -f yum_config/yum.repos.d/epel.repo /etc/yum.repos.d
sudo cp -f yum_config/yum.repos.d/nux-dextop.repo /etc/yum.repos.d
sudo cp -f yum_config/RPM-GPG-KEY-EPEL-7 /etc/pki/rpm-gpg
sudo cp -f yum_config/RPM-GPG-KEY-nux.ro /etc/pki/rpm-gpg
