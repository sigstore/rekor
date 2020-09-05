#!/bin/bash

DB="test"
USER="test"
PASS="zaphod"
ROOTPASS="p6ssw0rd"

echo -e "Creating $DB database and $USER user account"


mysql -uroot -p$ROOTPASS<<MYSQL_SCRIPT
DROP DATABASE IF EXISTS $DB;
CREATE DATABASE $DB;
CREATE USER IF NOT EXISTS '$USER'@'localhost' IDENTIFIED BY '$PASS';
GRANT ALL PRIVILEGES ON $USER.* TO '$DB'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT


echo -e "Loading table data.."

mysql -u $USER -p$PASS -D test < ./storage.sql
