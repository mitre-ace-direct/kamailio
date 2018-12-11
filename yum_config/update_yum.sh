sudo yum clean all
sudo cp yum.conf /etc/yum.conf
sudo rm -rf /etc/yum.repos.d
sudo cp -rf yum.repos.d /etc/yum.repos.d
sudo cp -f RPM* /etc/pki/rpm-gpg
