# 0=>LOW, 1=>MEDIUM, 2=>HIGH
#SET GLOBAL validate_password_policy=LOW;
#SET GLOBAL validate_password_length = 6;
#SET GLOBAL validate_password_number_count = 0;

uninstall plugin validate_password;
#INSTALL PLUGIN validate_password SONAME 'validate_password.so';
