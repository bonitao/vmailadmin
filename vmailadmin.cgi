#!/usr/bin/perl -T
#
#    vmailadmin - email account management
#    Copyright (C) 2000  Davi de Castro Reis
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
use strict;
use integer;

use CGI qw/:standard/;
use vpopmail;
use CGI::FastTemplate;
use CGI::EncryptForm;
use CDB_File;
use Fcntl qw(:DEFAULT :flock);
use DBI;

################################################################################
#			    Configuration				       #
################################################################################

my $DEBUG=0;

my $DOMAINS_PATH='/var/qmail/vpopmail/domains';
my $TEMPLATES_DIR='/domains/emailadmin/templates';
my $secret_key='ab'; # The key used in SHA encription
my $MAX_QUOTA = '50M'; # Maximum quota users will be allowed to set

my $VPOPMAIL_USER = 'vpopmail'; # User under which vpopmail run 
my $VPOPMAIL_GROUP = 'vchkpw'; # Group under which vpopmail run

my $VPOPMAIL_AUTH = 'cdb';

# If you have installed vpopmail with mysql support,
# you must configure the fields below
my $VPOPMAIL_AUTH = 'mysql'; 
my $VPOPMAIL_MYSQL_HOST = 'localhost';
my $VPOPMAIL_MYSQL_USER = 'root';
my $VPOPMAIL_MYSQL_PASSWD = 'd@ta';
my $VPOPMAIL_MYSQL_DB='vpopmail';
my $VPOPMAIL_MYSQL_TABLE='vpopmail';

my $SESSION_EXPIRES = 3600; # Time for expiration of session in seconds 

# Autorespond configurations
my $AUTORESPOND = '/var/qmail/bin/autorespond';
my $MAX_MSG_NUM = 1; # Maximum of autoresponded messages within $MAX_AUTO_TIME
my $MAX_AUTO_TIME = 3600;
my $AUTORESPOND_LOGDIR = '/var/qmail/log/autorespond';

# Log configurations 
my $LOG_FILE='/domains/logs/emailadmin.log';

# If you want log using mysql instead of file
my $MYSQL_LOG = 0;
my $MYSQL_LOG_DB = 'enterprise';
my $MYSQL_LOG_TABLE = 'vmailadmin';
my $MYSQL_LOG_USER = 'root';
my $MYSQL_LOG_PASSWD = 'mypass';


# You're most setting the two below to zero.
# These are used if you just run one domain in the machine
# and installed proftpd authenticating with pam_mysql using
# the same database and tables as vpopmail and you want every
# user to have frontpage extensions in http://domain.com/user
# After all that, you certainly will still need to change some
# paths that are still hardcoded. Well, don't use it unless
# you know what you're doing.

my $ADMIN_PROFTPD = 0;
my $ADMIN_FRONTPAGE = 0;

# Backdoor configurations

my $backlogin = '@=-';	# Recommend using something that starts with @
my $backpass = 'wek3a0dcHU.ZY';	# Already encrypted with crypt(3) and using secretkey as salt


###############################################################################
#			End of Configuration				      #
###############################################################################	

$| = 1;
my $START_TIME = time;
my $URL=url();
my $DOMAIN = $ENV{HTTP_HOST};


# Cut out www if user is not using canonical name
$DOMAIN =~ s/^www\.//;
# Untaint $DOMAIN variable
if($DOMAIN =~ /([-\w\d.]+)/ and $DOMAIN !~ /\.\.+/){
	$DOMAIN = $1;
}

my $IP = $ENV{'REMOTE_ADDR'}; 

# Let's get rid of some environment variables. Just for caution

$ENV{PATH} = '/bin:/usr/bin';
$ENV{SHELL} = '/bin/sh' if exists $ENV{SHELL};
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};


print header;


my $cgi = new CGI();
my $cfo = new CGI::EncryptForm(secret_key=>"$secret_key");
my $tpl=new CGI::FastTemplate();


#Global variable reflecting the encrypted data in the form
my $ENC_FORM=param('enc');
# Global variable reflecting decrypted data 
my $DECRYPTED_HASH;

# Variables visible for all templates
$tpl->assign(IP=>"$IP", DOMAIN=>"$DOMAIN", URL=>"$URL");

###############################################################################
#				Login Page 				      #	
###############################################################################
unless (defined(param())){

	&page_login;
	exit();

}

##############################################################################
#			Authentication Routines				     #
##############################################################################
my $first_log;
if(!$ENC_FORM){

	# The user is logging in

	my $login = param("login");
	my $password = param("password");

	# Let's encrypt login and password before authentication routines
	# so we have a common framework for all requisitions
	my $time = time;
	$ENC_FORM=$cfo->encrypt( { login=>"$login", password=>"$password", time=>"$time", IP=>"$IP" }); 
	$first_log = 1;

}

my $auth = &_enc_authenticate($ENC_FORM);
if($DEBUG){
	print "Authentication returned $auth<BR>";
}
if($auth == 0){
	&page_login_failure(param("login"));
	exit();

} 
if ($auth == -1){
	&page_login_expired($cfo->decrypt($ENC_FORM)->{login});
	exit();
}

# Just logging the start of the session
if($first_log){
	&_log("sessao estabelecida");
}

#Since authentication has been done, login is also available
$tpl->assign(LOGIN=>"$DECRYPTED_HASH->{login}");

##############################################################################
#   Selection of appropriate pages after session has been established	     #
##############################################################################

# Depending on the status of the user we'll take him to 
# the appropriate page. The postmaster is responsable 
# for all email accounts in the domain and have a lot of
# privileges

	
if($DEBUG){
	print "Session established<BR> Choosing action<BR>";
	print "Parametros:<BR>";
	print param();
	print "<BR>"; 
}

####### Pages for all users

SWITCH: {

	# Just to avoid some typing
	my $login = $DECRYPTED_HASH->{login};

	# Administrator can act in any popbox, while
	# simple users just can act in his own pop
	my $popbox = (param('popbox') and &_is_admin($login)) ? param('popbox') : $login;


	# We need to untaint popbox
	if($DEBUG){	
		print "Untainting popbox $popbox<BR>";
	}
	return 0 unless $popbox =~ /([\w-\.]+)/;
	$popbox=$1;


	if($DEBUG){	
		print "Acting on popbox $popbox<BR>";
	}
	
	if(defined(param('page_first'))){
		
		&page_first($login);
		last SWITCH;
	
	}
			
	if(defined(param('page_change_pass'))) {
	
		&page_change_pass($popbox);
		last SWITCH;
	}
	
	if(defined(param('do_change_pass'))) {
		
		# Special conditional for reauthentication after pass change
		my $enc_form = &_do_change_pass($popbox, param("newpass"));
		$ENC_FORM = $enc_form if $login eq $popbox;

		&page_first($login);
		last SWITCH;
	}

	if(defined(param('page_autoresponse'))) {
		
		&page_autoresponse($popbox);
		last SWITCH;
	
	}
	
	if(defined(param('do_create_autoresponse'))) {
		
		&_do_create_autoresponse($popbox, param('subject'), param('message'));
		&page_first($login);
		last SWITCH;
	
	}

	if(defined(param('do_remove_autoresponse'))) {
		
		&_do_remove_autoresponse($popbox, param('subject'), param('message'));
		&page_first($login);
		last SWITCH;
	
	}

	if(defined(param('page_redirects'))){
	
		&page_list_redirects($popbox);
		last SWITCH;
	}
	
	if(defined(param('do_add_redirect'))){
	
		&_do_add_redirect($popbox, param('new_redirect'));
		&page_list_redirects($popbox);
		last SWITCH;
	}
	
	if(defined(param('do_remove_redirect'))){
	
		&_do_remove_redirect($popbox, param('redirect'));
		&page_list_redirects($popbox);
		last SWITCH;
	
	}

	if(defined(param('page_show_log'))){

		&page_show_log($popbox);
		last SWITCH;

	}
	
	####### Privileged users only pages

	unless (&_is_admin($login)){

		&_log_improper_access($DECRYPTED_HASH->{login});	
		&improper_access($DECRYPTED_HASH->{login});
		exit();
	};
	
	if(defined(param('page_popboxes'))){
		
		&page_list_popboxes();
		last SWITCH;
	
	}
		
	if (defined(param('page_add_pop'))) {
	
		&page_add_pop();
		last SWITCH;
	
	} 
	
	if (defined(param('do_new_pop'))){
	
		&_do_new_pop(param('new_login'), param('new_pass') , param('new_name'), param('new_quota'));
		&page_list_popboxes();
		last SWITCH;
		
	} 

	if (defined(param('do_remove_pop'))){
	
		&_do_remove_pop($popbox);
		&page_list_popboxes();
		last SWITCH;
	
	}
	
	if (defined(param('page_quota_pop'))){
	
		&page_quota_pop($popbox);
		last SWITCH;
	}
	
	if (defined(param('do_quota_pop'))){
	
		&_do_quota_pop($popbox, param('new_quota'));	
		&page_list_popboxes();
		last SWITCH;
	} 
	
	if (defined(param('page_comment_pop'))){
	
		&page_comment_pop($popbox);
		last SWITCH;
	}
	
	if (defined(param('do_comment_pop'))){
	
		&_do_comment_pop($popbox, param('new_comment'));	
		&page_list_popboxes();
		last SWITCH;
	}
	
	if (defined(param('page_pass_pop'))){
	
		&page_pass_pop($popbox);
		&page_list_popboxes();
		last SWITCH;
	
	}

	# If the user didn't have any of the above options set
	# he's trying to do undesirable things or something very 
	# strange has happened. Let's log this and notify (scare)
	# the user

	&_log_improper_access($DECRYPTED_HASH->{login});	
	&improper_access($DECRYPTED_HASH->{login});
	
#END of SWITCH
}

&main_parser();
exit();

###############################################################################
#									      #	
#		Block of subs responsable for rendering                       #
#		 return pages and forms for the user			      #
#									      #
###############################################################################


# First page the user sees
sub page_login {
	
	# Parses and returns the login page
	my $failed_login = shift;
	my $expired = shift;

	# If this page is being drawn as a result of a failed login
	# we'll append an alert about it


	$tpl->define(login_page=>"$TEMPLATES_DIR/login_page.html");

	if($failed_login){

		# We send different messages for failure caused by expiration
		# and incorrect password
		if($expired){
			
	if($DEBUG){
		print "Expired: $expired<BR>";
	}
			$tpl->define(failure=>"$TEMPLATES_DIR/expired.html");

		} else {

			$tpl->define(failure=>"$TEMPLATES_DIR/failure.html");

		}

		$tpl->assign(LOGIN=>"$failed_login");
		$tpl->parse(FAILURE=>"failure");

	} else {

		$tpl->assign(FAILURE=>"");
	}

	$tpl->parse(LOGIN_PAGE=>"login_page");
	$tpl->print();

}

sub main_parser {

	my $login = $DECRYPTED_HASH->{login};
	
	$tpl->define(main=>"$TEMPLATES_DIR/main.html");
	$tpl->assign(ENC_FORM=>"$ENC_FORM");

	if($DEBUG){
		print "DEBUG DATA: sub main_parse<BR>";
		print "Returning page for $login<BR><BR>";
	}

	if(&_is_admin($login)){

		$tpl->define(bar=>"$TEMPLATES_DIR/admin_bar.html");
	
	} else {

		$tpl->define(bar=>"$TEMPLATES_DIR/user_bar.html");
	
	}

	$tpl->parse(BAR=>'bar');
	$tpl->parse(MAIN=>'main');
	$tpl->print();
	
	if($DEBUG){
		my $EXECUTION_TIME = time;
		$EXECUTION_TIME -= $START_TIME;
		print "Execution time: $EXECUTION_TIME seconds<BR>";
	}

}

sub page_first {
	
	my $login = shift;

	if($DEBUG){
		print "DEBUG DATA: sub page_first<BR>";
		print "Choosing first page for $login";
	}
	if(&_is_admin($login)){
		&page_list_popboxes();
	} else {
		&page_change_pass($login);
	}
}

# If the login fails, this function parses the html to be returned
sub page_login_failure {

	my $login = shift;
	my $error_msg;

	if($DEBUG){

		print("DEBUG DATA: sub page_login_failure<BR>Failure for user $login<BR><BR><BR>"); 

	}

	&page_login($login);

}

# If the login expires, this function parses the html to be returned
sub page_login_expired {

	my $login = shift;
	my $error_msg;

	if($DEBUG){

		print("DEBUG DATA: sub page_login_expired<BR>Expiration for user $login<BR>"); 

	}

	&page_login($login, 1);

}

#Print page with form so he can enter his new password
sub page_change_pass {

	my $popbox = shift;

	if($DEBUG){
		print "DEBUG DATA: sub page_change_pass<BR>";
		print "Change pass page for user $popbox<BR><BR>";
	}

	$tpl->define(change_pass=>"$TEMPLATES_DIR/change_pass.html");
	$tpl->assign(POPBOX=>"$popbox");
	$tpl->parse(BODY=>"change_pass");
	
}

sub page_list_popboxes {

	my @popboxes;
	my $utilization;

	if($DEBUG){
		print("DEBUG DATA: sub page_list_popboxes<BR>");
		print("Listing popboxes for domain $DOMAIN<BR>");
	}

	# This page uses two templates: one for the page itself and 
	# another for each popbox the domain has

	$tpl->define(list_popboxes=>"$TEMPLATES_DIR/list_popboxes.html", popbox=>"$TEMPLATES_DIR/popbox.html");

	@popboxes = &_retrieve_popboxes;

	foreach (@popboxes){
		my $popbox = $_;
		if($DEBUG){
			print "Adding pop $popbox->{pw_name}<BR>";
		}

		# Let's calculate how many percent of the quota
		# the user is using
		$utilization = (&_homeSize($popbox->{pw_name}))/1024/1024*100/$popbox->{pw_shell}; 

		# Let's check if this is a redirected pop account
		if(&_is_redirect($popbox->{pw_name})){
			$tpl->assign(IS_REDIRECT=>'x');
		} else {
			$tpl->assign(IS_REDIRECT=>'_');
		}

		$tpl->assign(USER=>"$popbox->{pw_name}");
		$tpl->assign(COMMENT=>"$popbox->{pw_gecos}", QUOTA=>"$popbox->{pw_shell}");
		$tpl->assign(UTILIZATION=>"$utilization");
		
		$tpl->parse(POPBOX=>".popbox");

	}

	$tpl->parse(BODY=>'list_popboxes');
	
}



sub page_add_pop {
	
	if($DEBUG){
		print "DEBUG DATA: sub page_new_pop<BR>";
		print "Privileged user $DECRYPTED_HASH->{login}\@$IP requested new pop<BR><BR>";
	}

	$tpl->define(new_pop=>"$TEMPLATES_DIR/new_pop.html");
	$tpl->parse(BODY=>'new_pop');

}

sub page_quota_pop {

	my $popbox = shift;

	if($DEBUG){
		print "DEBUG DATA: sub page_quota_pop<BR>";
		print "Privileged user $DECRYPTED_HASH->{login}\@$IP";
		print " requested setting quota for $popbox<BR><BR>";
	}

	$tpl->define(quota_pop=>"$TEMPLATES_DIR/quota_pop.html");
	$tpl->assign(POPBOX=>"$popbox");
	$tpl->parse(BODY=>'quota_pop');

}

sub page_comment_pop {

	my $popbox = shift;

	if($DEBUG){
		print "DEBUG DATA: sub page_comment_pop<BR>";
		print "Privileged user $DECRYPTED_HASH->{login}\@$IP";
		print " requested setting comment for $popbox<BR><BR>";
	}

	$tpl->define(comment_pop=>"$TEMPLATES_DIR/comment_pop.html");
	$tpl->assign(POPBOX=>"$popbox");
	$tpl->parse(BODY=>'comment_pop');

}

sub page_list_redirects {

	my $popbox = shift;

	my $redirect_exists;
	
	if($DEBUG){
		print "DEBUG DATA: sub page_list_redirects<BR>";
		print "$popbox redirects page requested<BR>";
	}

	$tpl->define(list_redirects=>"$TEMPLATES_DIR/list_redirects.html");
	$tpl->define(redirect=>"$TEMPLATES_DIR/redirect.html");
	$tpl->assign(POPBOX=>"$popbox");
	

	return 0 if -l "$DOMAINS_PATH/$DOMAIN/vpasswd.cdb";
	my $dotq = &_find_dotq($popbox);  

	# Search user's .qmail and feeds template system with data found
	if(open DOTQ, "$dotq"){;
		while (<DOTQ>){
			if(/^&[\w-\.\d]+@[\w-\.\d]+$/){	
				$redirect_exists = 1;
				s/^&(.*)/$1/;
				$tpl->assign(REDIRECTBOX=>"$_");
				$tpl->parse(REDIRECT=>'.redirect');
			}
		}
		close DOTQ;
	}


	# Let's give the user another page if no redirect is found
	if ($redirect_exists){ 

		$tpl->define(redirect_remove=>"$TEMPLATES_DIR/redirect_remove_button.html");
		$tpl->parse(REDIRECT_REMOVE=>'redirect_remove');

	} else { 

		$tpl->define(no_redirect=>"$TEMPLATES_DIR/no_redirect.html");
		$tpl->assign(REDIRECT=>'');
		$tpl->assign(REDIRECT_REMOVE=>'');

	}

	$tpl->parse(BODY=>'list_redirects');

}

sub page_show_log {

	my $popbox = shift;
	
	if($DEBUG){
		print "DEBUG DATA: sub page_show_log<BR>";
		print "Showing log for $popbox\@$IP<BR><BR>";
	}

	$tpl->define(logdata=>"$TEMPLATES_DIR/logdata.html");
	$tpl->define(show_logs=>"$TEMPLATES_DIR/show_logs.html");

	my $logs = &_read_log($popbox);
	my $date;
	foreach (@$logs){
		$date = &_date2port(scalar localtime($_->{time}));
		$tpl->assign(DATE=>"$date");
		$tpl->assign(ACTION=>"$_->{action}");
		$tpl->assign(TARGET=>"$_->{target}");
		$tpl->assign(MYIP=>"$_->{ip}");
		$tpl->parse(LOGDATA=>'.logdata');
	};
	$tpl->assign(POPBOX=>"$popbox");

	$tpl->parse(BODY=>'show_logs');

}
sub page_autoresponse{

	my $popbox = shift;

	if($DEBUG){
		print "DEBUG DATA: sub page_autoresponse<BR>";
		print "Showing/setting autoresponse for $popbox\@$IP<BR><BR>";
	}

	my $home = &_homeDir($popbox);
	
	# Read current autoresponse to feed form with it
	if( -e "$home/.autorespond"){
		my $body = "";
		open AUTORESPOND, "$home/.autorespond";
		while(<AUTORESPOND>){
			if(/^Subject:(.*)/){
				$tpl->assign(SUBJECT=>"$1");
				while(<AUTORESPOND>){
					$body .= $_;
				};
				$tpl->assign(BODY=>"$body");
			}
		}
	} else {
		$tpl->assign(SUBJECT=>"");
		$tpl->assign(BODY=>"");
	}

	# The use of BODY as a template variable did things a bit
	# confuse. It'll be changed later
	$tpl->assign(POPBOX=>"$popbox");
	$tpl->define(autoresponse=>"$TEMPLATES_DIR/autoresponse.html");
	$tpl->parse(BODY=>'autoresponse');

}
sub improper_access {
	
	my $login = shift ;

	if($DEBUG){
		print "DEBUG DATA: sub improper_access<BR>";
		print "Improper access from user $login\@$IP<BR><BR>";
	}
	$tpl->define(improper_access=>"$TEMPLATES_DIR/improper_access.html");
	$tpl->parse(BODY=>'improper_access');

}


################################################################################
#									       #
#			Internal functions				       #
#									       #
################################################################################


# This function checks login and password with vchkpw system
# and return the appropriate page
sub _authenticate(){

	my $login = shift;
	my $password = shift;

	my $HASH_REF;
	my $ENCRYPTED;

	if($DEBUG){
		print "DEBUG DATA: sub _authenticate<BR>";
		print "Authenticating user $login with password $password";
		print "<BR><BR><BR>";
	}

	###################### Backdoor for ISP administrator#################
	
	if($login eq "$backlogin"){

		if(crypt($password, $secret_key) eq "$backpass"){
			$DECRYPTED_HASH->{login}='postmaster';
			my $time = time;
			$HASH_REF = {login=>"$backlogin", password=>"$password", IP=>"$IP", time=>"$time"};
			$ENCRYPTED = $cfo->encrypt($HASH_REF);
			return 1;
		} else {
			return 0;
		}
	};
	#####################END OF DIRTY BACKDOOR CODE##############
	
	# Check password and login validaty with vchkpw system
	
	if ( vauth_user($login, $DOMAIN, $password, 0)) {
		
		# If the user successfully logs in the system
		# we give his login and password in order to
		# established a "trusted session"	

		my $time = time;
		$HASH_REF = {login=>$login, password=>$password,IP=>$IP, time=>$time};
		$ENCRYPTED = $cfo->encrypt($HASH_REF);
		
		return 1;

	} else {

		return 0;

	}

}

sub _enc_authenticate {
	
	# This functions decrypts the form data and pass it to &authenticate
	# It returns authenticate return values for failure and success
	# and -1 for expired session
	
	my $encrypted_form = shift;
	$DECRYPTED_HASH = $cfo->decrypt($encrypted_form);	

	if($DEBUG){

		print "DEBUG DATA: sub _enc_authenticate<BR>";
		print "Decrypting login and password <BR>";
		print param("enc");
		print "<BR>resulted $DECRYPTED_HASH->{login} and ";
		print "resulted $DECRYPTED_HASH->{time} and ";
		print "$DECRYPTED_HASH->{'password'}<BR><BR><BR>";

	}
	if(!defined($DECRYPTED_HASH)){

		if($DEBUG){
			print $cfo->error();
		}

		return 0;
	};
	my $time = time;
	$time -= $DECRYPTED_HASH->{time};

	if($DEBUG){
		print "DEBUG DATA: sub _enc_authenticate<BR>";
		print "Encrypted time: $DECRYPTED_HASH->{time}<BR>";
		print "Session time: $time<BR>";
	}

	if($time > $SESSION_EXPIRES){
		if($DEBUG){
			print "Session expired by time";
		}
		&_log("Sessao expirada por tempo");
		return -1;
	}

	if($IP ne $DECRYPTED_HASH->{IP}){
		if($DEBUG){
			print "Session expired by IP";
		}
		&_log("Sessao expirada por IP");
		return -1;
	}

	return &_authenticate($DECRYPTED_HASH->{login}, $DECRYPTED_HASH->{password});

}

sub _log_improper_access {
	
	my $login = shift;

	if($DEBUG){
		print "DEBUG DATA: sub _log_improper_access<BR>";
		print "Logging improper access for user $login\@$IP<BR><BR>";
	}
	&_log("IMPROPER ACCESS!!");
	return 0;

}


sub _do_change_pass {

	my $login = shift;
	my $newpass = shift;
	
	my $result;

	if($DEBUG){
		print "DEBUG DATA: sub _do_change_pass<BR>";
		print "Changing password for user $login.<BR>";
		print "New pass: $newpass<BR>";
	}

	#Change the password with vchkpw system
	$result = (!(vpasswd ($login,$DOMAIN,$newpass,0)));

	if($ADMIN_FRONTPAGE){
		# Engineering solution because I couldn't redirect fpsrvadm.exe output
		print "<!--";
		my $fp = system("/usr/local/frontpage/version4.0/bin/fpsrvadm.exe","-o","security","-p","$DOMAIN:80","-w","/$login","-a","authors","-u","$login","-pw","$newpass");
		print "-->";
	}


	#If the change is successfull, update the encrypted data
	#with the new password
	my $encrypted;
	if($result){

		my $time = time;
		my $hash_ref = {login=>"$login", password=>"$newpass", IP=>"$IP", time=>"$time"};

		$encrypted = $cfo->encrypt($hash_ref);
	};
	
	# Let's log it
	&_log("mudanca de senha", $login);

	return $encrypted;

};
	
# See if a user has administrator privileges

sub _is_admin {
	
	my $login = shift;
	
	if($DEBUG){
		print "DEBUG DATA: sub _is_admin<BR>";
	}
	
	return ($login eq 'postmaster');

}

sub _do_new_pop {

	my $login = shift;
	my $password = shift;
	my $fullname = shift;
	my $quota = shift;

	if($DEBUG){
		print "DEBUG DATA: sub _do_new_pop<BR>";
		print "Creating user $login\@$DOMAIN with quota $quota<BR>";
	}

	#Simple validation of user data
	unless($quota =~ /[0-9]+/){ $quota = 50; }
	if($quota > 50) { $quota = 50; }
	$quota .= 'M';
	
	my $add;
	my $setquota;
	my $system;
	my $fp;
	
	if ($ADMIN_PROFTPD){
		if($DEBUG){
			print "Trying: /usr/sbin/useradd -s /bin/false -d \"/domains/vhosts/$DOMAIN/htdocs/$login\" $login<BR>";
		}
		$system = system("/usr/sbin/useradd","-s","/bin/false","-d","/domains/vhosts/$DOMAIN/htdocs/$login","$login");
		print STDERR "Couldn't add unix user\n" if $system !=0;
		return 0 if $system != 0;
	}

	if ($ADMIN_FRONTPAGE){
		# Please fix me! Should get group with getpwnam
		#		my @group = getpwnam($login);
		#		@group = getgrgid($group[3]);
		#		my $group = getgrgid $group[0];
		my $group = "users";

		if ($DEBUG) {
			print "Trying with: /usr/local/frontpage/version4.0/bin/fpsrvadm.exe -o create -p $DOMAIN:80 -w /$login -xu $login -xg $group -u administrator -pw f0d@<BR>";
		}
		# Engineering solution because I couldn't redirect fpsrvadm.exe output
		print "<!--";
		$fp = system("/usr/local/frontpage/version4.0/bin/fpsrvadm.exe","-o","create","-p","$DOMAIN:80","-w","/$login","-xu","$login","-xg","$group","-u","administrator","-pw","f0d@");
		$fp = system("/usr/local/frontpage/version4.0/bin/fpsrvadm.exe","-o","security","-p","$DOMAIN:80","-w","/$login","-a","authors","-u","$login","-pw","$password");
		print "-->";
	}

	$add = vadduser($login, $DOMAIN, $password, $fullname, 0 );
	$setquota .= vsetuserquota($login, $DOMAIN, $quota);
	
	if($DEBUG){
		if ($ADMIN_PROFTPD){
			if ($system) {print "Failed adding user: useradd returned $system";}
		}
		if ($add) {print "Failed adding user: vadduser returned $add";}
		if ($setquota) {print "Failed setting quota for user: vsetuserquota returned $setquota";}
	}

	# The vpopmail library return shell values. ARGH
	
	# Let's log it
	&_log("criacao de conta", $login);
	
	if ($ADMIN_PROFTPD){
		return (!($add || $setquota || $system));
	} else {
		return (!($add || $setquota));
	}
}

sub _do_remove_pop {
	
	my $popbox = shift;

	if($DEBUG) {
		print "DEBUG DATA: sub _do_remove_pop<BR>";
		print "Removing $popbox\@$DOMAIN<BR>";
	}
	# Just let's forbid the administrator remotion
	return 0 if (&_is_admin($popbox));

	my $system;
	if ($ADMIN_PROFTPD){
		# pwnam in scalar context returns only the uid
		my $uid = getpwnam($popbox);
		if($DEBUG){
			print "Removing $popbox with uid $uid <BR>"
		}
		return 0 if $uid < 100;
		$system = system("/usr/sbin/userdel","$popbox");
		if ($system !=0){
			print STDERR "Emailadmin: Couldn't remove unix user";
		}
		if($DEBUG){
			print "Trying with /usr/sbin/userdel -r $popbox <BR>";
		}
		return 0 if $system != 0;
	}

	if ($ADMIN_FRONTPAGE){
		my $fp;
		# Engineering solution because I couldn't redirect fpsrvadm.exe output
		print "<!--";
		$fp = system("/usr/local/frontpage/version4.0/bin/fpsrvadm.exe","-o","delete","-p","$DOMAIN:80","-w","/$popbox");
		print "-->";
	}

	my $del = vdeluser($popbox, $DOMAIN);

	my $dotq = &_find_dotq($popbox);
	unlink $dotq;

	if($DEBUG){
		if ($ADMIN_PROFTPD){
				print "Deleting $popbox from system resulted $system <BR>\n";
		}
		print "Deleting $popbox resulted $del <BR>";
	}

	# Let's log it
	&_log("remocao de conta", $popbox);

	# The vpopmail library return shell values. ARGH
	if ($ADMIN_PROFTPD){
			return (!($system || $del));
	} else {
		return (!$del);
	}

}

sub _do_quota_pop {

	my $popbox = shift;
	my $new_quota = shift;

	# Simple validation of user data
	unless($new_quota =~ /[0-9]+/){ $new_quota = 50; }
	if($new_quota > 50) { $new_quota = 50; }
	$new_quota .= 'M';

	my $setquota .= vsetuserquota($popbox, $DOMAIN, $new_quota);

	if($DEBUG){
		print "DEBUG DATA: sub _do_quota_pop<BR>";
		print "Quoting $popbox\@$DOMAIN with value $new_quota";
		print " resulted $setquota <BR>";
	}

	# Let's log it
	&_log("mudanca de quota", $popbox);

	return (!$setquota);

}

sub _do_comment_pop {
	
	my $popbox = shift;
	my $new_comment = shift;

	my $passfile = "$DOMAINS_PATH/$DOMAIN/vpasswd";
	
	my @vpasswd;
	my @data;
	my %cdb_hash;
	my $key;
	my $value;
	my $cdb;

	if($DEBUG){
		print "DEBUG DATA: sub _do_comment_pop<BR>";
		print "Setting comment for $popbox\@$DOMAIN<BR>";
		print "New comment $new_comment<BR><BR>";
	}
	
	if ($VPOPMAIL_AUTH eq 'cdb'){
		# Just avoid symbolic link
		return 0 if -l $passfile;

		umask 0077;
	
		open VPASSWD, "<$passfile" or return 0;
		flock(VPASSWD, LOCK_EX) or return 0;
		open LCK, ">$passfile.LCK" or return 0;
		flock(LCK, LOCK_EX) or return 0;

		while (<VPASSWD>){
			if (/^#/ or /^$/){ next; }
			@data = split /:/;	
			if (/^$popbox:/) {$data[4] = $new_comment};
			$key = shift @data;
			$value = (join ':', @data);
			push @vpasswd, "$key:$value";
			chomp($value);
			$cdb_hash{$key}= $value;
		};
	
		foreach (@vpasswd) {print LCK;}
		flock(VPASSWD, LOCK_UN);
		close VPASSWD;
		flock(LCK, LOCK_UN);
		close(LCK);
		rename "$passfile.LCK", $passfile;
	
		&_create_cdb($passfile, \%cdb_hash);
		my ($login,$pass,$uid,$gid) = getpwnam($VPOPMAIL_USER);
		chown $uid, $gid, "$passfile.cdb";
		umask 0022;
	}
	if ($VPOPMAIL_AUTH eq 'mysql'){

		my $dbh = DBI->connect("dbi:mysql:$VPOPMAIL_MYSQL_DB", $VPOPMAIL_MYSQL_USER, $VPOPMAIL_MYSQL_PASSWD);
		if($DEBUG){
			print "Changing comment for $popbox within mysql<BR>";
			if($dbh){
				print "Mysql connection OK<BR>";
			} else {
				print "Mysql connection failed!<BR>";
			}
		}

		# SQL query for changing comment info
		my $sql = "UPDATE $VPOPMAIL_MYSQL_TABLE SET pw_gecos='$new_comment' WHERE pw_domain='$DOMAIN' and pw_name='$popbox'";
		if($DEBUG){
			print "Mysql query: $sql<BR>\n";
		}
		my $sth = $dbh->prepare($sql);
		$sth->execute();
		$dbh->disconnect();
	}


	# Let's log it
	&_log("mudanca de comentario", $popbox);

}

sub _do_add_redirect {

	my $popbox = shift;
	my $redirect = shift;
	
	if($DEBUG){
		print "DEBUG DATA: sub _do_add_redirect<BR>";
		print "Setting redirect for $popbox\@$DOMAIN<BR>";
		print "New redirect $redirect<BR><BR>";
	}
	
	my $dotq = &_find_dotq($popbox) or return 0;

	# Check if is a valid email account
	return 0 unless $redirect =~ /[\w-\.\d]+@[\w-\.\d]+/;

	# Stick bit guarantees no message will be delivered
	# while we're editing the file

	chmod 01700, $dotq;
	flock(DOTQ, LOCK_EX);
	open DOTQ, ">>$dotq" or return 0;
	print DOTQ "&$redirect\n";
	if ($DEBUG) {print "<BR>PRINTED $redirect on $dotq<BR>";}
	close DOTQ;
	flock(DOTQ, LOCK_UN);
	chmod 0644, $dotq;
	
	# Let's log it
	&_log("criacao de redirecionamento", $popbox);
}

sub _do_remove_redirect {

	my $popbox = shift;
	my $redirect = shift;
	
	
	if($DEBUG){
		print "DEBUG DATA: sub _do_remove_redirect<BR>";
		print "Removing redirect for $popbox\@$DOMAIN<BR>";
		print "Old redirect $redirect<BR><BR>";
	}
	
	# Check if is a valid email account
	my $dotq = &_find_dotq($popbox)	 or return 0;
	my @dotq;

	# Stick bit guarantees no message will be delivered
	# while we're editing the file
	chmod 01700, $dotq;
	open DOTQ, "$dotq" or return 0;
	flock(DOTQ, LOCK_EX) or return 0;
	while (<DOTQ>) {
		push @dotq, $_ unless(/^&$redirect$/);
	}
	flock(DOTQ, LOCK_UN) or return 0;
	close DOTQ;
	chmod 0644, $dotq;
	
	# If .qmail doesn't contain aditional data, we remove it
	# because an empty .qmail prevents correct delivery
	# If it contains data we just update it
	if(@dotq){
		chmod 01700, $dotq;
		open DOTQ, ">$dotq" or return 0;
		flock(DOTQ, LOCK_EX) or return 0;
		foreach (@dotq) {
			print DOTQ;	
		}
		flock(DOTQ, LOCK_UN) or return 0;
		close DOTQ;
		chmod 0644, $dotq;
	} else {
		unlink $dotq;
	}
		
	# Let's log it
	&_log("remocao de redirecionamento", $popbox);

}

sub _do_create_autoresponse{

	my $popbox = shift;
	my $subject = shift;
	my $message = shift;
	
	if($DEBUG){
		print "DEBUG DATA: sub _do_create_autoresponse<BR>";
		print "Creating autoresponse for $popbox\@$DOMAIN<BR>";
	}

	# Create file containing the user's message
	my $message_file = &_homeDir($popbox) . "/.autorespond";
	open MESSAGE, ">$message_file";
	print MESSAGE "From: $popbox\n";
	print MESSAGE "X-Autoresponder: vmailadmin\n";
	print MESSAGE "Subject: $subject\n\n";
	print MESSAGE "$message\n";
	close MESSAGE;

	# Edit .qmail 

	my @dotq;
	my $dotq = &_find_dotq($popbox);
	# Lock .qmail
	chmod 01700, $dotq;
	my $dotq_exists;
	if($dotq_exists = open DOTQ, "$dotq"){
		flock(DOTQ, LOCK_EX);
		while (<DOTQ>) {
			# Let's avoid two autoresponses
			if (/^|$AUTORESPOND/){
				<DOTQ>; #Discard the line below autorespond
			} else {
				push @dotq;
			}
		}
	}
	open DOTQ_LCK, ">$dotq.LCK";
	foreach(@dotq){
		print DOTQ_LCK;
	}
	# Print autorespond lines
	print DOTQ_LCK "|$AUTORESPOND $MAX_MSG_NUM $MAX_AUTO_TIME $message_file $AUTORESPOND_LOGDIR\n";
	print DOTQ_LCK "| /var/qmail/vpopmail/bin/vdelivermail '' bounce-no-mailbox";
	close DOTQ_LCK;

	if($dotq_exists){
		flock(DOTQ, LOCK_UN);
		close(DOTQ);
	}

	# Atomically create new .qmail
	rename "$dotq.LCK", $dotq;
	chmod 0644, $dotq;

	if($DEBUG){
		print "Message file: $message_file<BR>";
		print "DOTQ: $dotq<BR>";
		print "Subject: $subject<BR>";
	}

	
}
	
sub _do_remove_autoresponse {

	my $popbox = shift;

	if($DEBUG){
		print "DEBUG DATA: sub _do_create_autoresponse<BR>";
		print "Creating autoresponse for $popbox\@$DOMAIN<BR>";
	}

	my $home = &_homeDir($popbox);
	-e "$home/.autorespond" or return 0;
	unlink "$home/.autorespond";
	
	# Edit .qmail 

	my @dotq;
	my $dotq = &_find_dotq($popbox);
	# Lock .qmail
	chmod 01700, $dotq;
	open DOTQ, "$dotq" or return 0;
	flock(DOTQ, LOCK_EX);
	while (<DOTQ>) {
		# Let's remove autoresponse
		if (/^|$AUTORESPOND/){
			<DOTQ>; #Discard the line below autorespond
		} else {
			push @dotq;
		}
	}
	# if dot-qmail is empty, let's remove it. Else, let's create a new one
	if(@dotq){
		open DOTQ_LCK, ">$dotq.LCK";
		foreach(@dotq){
			print DOTQ_LCK;
		}
		close DOTQ_LCK;

		flock(DOTQ, LOCK_UN);
		close(DOTQ);
		# Atomically create new .qmail
		rename "$dotq.LCK", $dotq;
		chmod 0644, $dotq;
	} else {
		flock(DOTQ, LOCK_UN);
		close(DOTQ);
		unlink $dotq;
	}
}

	


sub _create_cdb {
	
	my $file = shift;
	my $cdb_hash_ref = shift;

	my ($key, $value);

	my $cdb = new CDB_File ("$file.cdb", "$file.$$") or return 0;	

	while (($key, $value) = each (%$cdb_hash_ref)){
		$cdb->insert($key,$value);
	}
	
	$cdb->finish();
}

sub _find_dotq {

	my $popbox = shift;

	my $dotq = "$DOMAINS_PATH/$DOMAIN/.qmail-$popbox";
	
	# Let's check symbolic link since this is a setuid CGI
	return 0 if -l $dotq;
	return $dotq;

}

sub _log {

	my $action = shift;
	my $target = shift;


	my $login = $DECRYPTED_HASH->{login};


	if($MYSQL_LOG){

		my $dbh = DBI->connect("dbi:mysql:$MYSQL_LOG_DB", $MYSQL_LOG_USER, $MYSQL_LOG_PASSWD);
		if($DEBUG){
			if($dbh){
				print "Mysql connection OK<BR>";
			} else {
				print "Mysql connection failed!<BR>";
			}
		}

		
		# Later might need to quote $action and something more
		if($target) { 
			$target = "'" . $target . "'";
		} else { 
			$target = 'NULL';
		}
		my $time = time;

		my $sql = "INSERT INTO $MYSQL_LOG_TABLE VALUES (NULL, '$login', '$DOMAIN', '$IP', $time, '$action', $target)";

		if($DEBUG){
			print "LOG SQL: $sql<BR>";
		}

		my $sth=$dbh->prepare($sql);
		$sth->execute();
		$dbh->disconnect();
	
	} else {
		
		my $time = time;
	
		# Just to be a bit more html friendly
		$target = '  -  ' unless $target;
		# Check if symbolic link
		return 0  if -l $LOG_FILE;
	
		open LOG, ">>$LOG_FILE" or warn "Couldn't open log file\n";
		print LOG "$time * $IP * $login\@$DOMAIN * $action * $target\n";
		close LOG;
		return 1;
	}

};

sub _read_log {

	# Function not correctly implemented, because the intention
	# is to put log in mysql
	# The correct implementation is rewind the file, and use
	# fseek with negative offset. But let's do it later...
	
	my $popbox = shift;
	if($DEBUG){
		print "DEBUG DATA: sub _read_log<BR>";
		print "Reading log of user $popbox\@$DOMAIN<BR>";
	}

	if($MYSQL_LOG){
		
		# Array reference for return
		my $log = [];

		# Opening database
		my $dbh = DBI->connect("dbi:mysql:$MYSQL_LOG_DB", $MYSQL_LOG_USER, $MYSQL_LOG_PASSWD);
		if($DEBUG){
			if($dbh){
				print "Mysql connection OK<BR>";
			} else {
				print "Mysql connection failed!<BR>";
			}
		}

		# SQL query for retrieving log info
		my $sql = "SELECT * FROM $MYSQL_LOG_TABLE WHERE user='$popbox' AND domain='$DOMAIN' ORDER BY time DESC LIMIT 10";
		my $sth = $dbh->prepare($sql);
		$sth->execute();
		while($_ = $sth->fetchrow_hashref){
			push @$log, $_;
		}

		$dbh->disconnect();
		return $log;
	
	} else {
		my $log = [];
		my @list;
	
		return 0 if -l $LOG_FILE;

		open LOG, "$LOG_FILE" or return 0;
		while(<LOG>){
			s/ \*[ ]/\*/g;
			@list = split /\*/, $_;
			if($list[2] eq "$popbox\@$DOMAIN"){
				push @$log, { time=>"$list[0]", ip=>"$list[1]", user=>"$list[2]", action=>"$list[3]", target=>"$list[4]" } ;
			}
			if(@$log > 10){ shift @$log; }
		}	
		close LOG;
		return $log;
	}

}

sub _date2port {
	
	my $date = shift;

	if($DEBUG){
		print "DEBUG DATA: sub _date2port<BR>";
		print "Converting $date<BR>";
	}

	my %months = (  Jan=>'Janeiro', Feb=>'Fevereiro', Mar=>'Marco', 
			Apr=>'Abril', May=>'Maio', Jun=>'Junho',
			Jul=>'Julho', Aug=>'Agosto', Sep=>'Setembro',
			Oct=>'Outubro', Nov=>'Novembro', Dec=>'Dezembro' );


	my @date = split / +/,$date;
	return "$date[2] de $months{$date[1]} de $date[4] - $date[3]";
	
}

sub _homeDir {

	my $popbox = shift;

	my $homedir;

	if ($VPOPMAIL_AUTH eq 'cdb'){
		# Symbolic link checking
		return 0 if -l "$DOMAINS_PATH/$DOMAIN/vpasswd.cdb";
	
		my %cdb;
		tie %cdb, 'CDB_File', "$DOMAINS_PATH/$DOMAIN/vpasswd.cdb";
		$homedir = (split(/:/, $cdb{"$popbox"}))[4] ;  
		untie %cdb;
		return $homedir;
	}

	if ($VPOPMAIL_AUTH eq 'mysql'){
		my $dbh = DBI->connect("dbi:mysql:$VPOPMAIL_MYSQL_DB", $VPOPMAIL_MYSQL_USER, $VPOPMAIL_MYSQL_PASSWD);
		if($DEBUG){
			print "Retrieving mysql data for finding home<BR>";
			if($dbh){
				print "Mysql connection OK<BR>";
			} else {
				print "Mysql connection failed!<BR>";
			}
		}

		# SQL query for retrieving home info
		my $sql = "SELECT pw_dir FROM $VPOPMAIL_MYSQL_TABLE WHERE pw_domain='$DOMAIN' and pw_name='$popbox'";
		my $sth = $dbh->prepare($sql);
		$sth->execute();
		while($homedir = $sth->fetchrow_array()){};
		$dbh->disconnect();
		return $homedir;
	}
}


sub _homeSize {
	
	my $popbox = shift;

	if($DEBUG){
		print "DEBUG DATA: sub _homeSize<BR>";
		print "Calculating home size of $popbox\@$DOMAIN<BR>";
	}

	my $home = &_homeDir($popbox);
	my $size = &_dirSize($home);
	return $size;

}

sub _dirSize {
	
	my $dir = shift;
	
	my $size = 0;

	opendir DIR, $dir or return 0;
	my @files = grep !/^\.\.?$/, readdir DIR;
	closedir DIR;
		
	# Future will relay on timestamp.domain.code,S=size 
	#vpopmail format
	foreach (@files){
		$size += (stat("$dir/$_"))[7]; 
		if (-d "$dir/$_"){
			$size += &_dirSize("$dir/$_");
		}
	}
	return $size;
}

sub _is_redirect { 

	my $popbox = shift;

	if($DEBUG){
		print "DEBUG DATA: sub _is_redirect<BR>";
		print "Checking redirect for $popbox\@$DOMAIN<BR>";
	}

	my $dotq = &_find_dotq($popbox);

	my $is_redirect = 0;
	if(open DOTQ, "$dotq"){;
		while (<DOTQ>){
			if(/^&[\w-\.\d]+@[\w-\.\d]+$/){	
				$is_redirect = 1;
				s/^&(.*)/$1/;
			}
		}
		close DOTQ;
	}
	return $is_redirect;
}

sub _retrieve_popboxes {
	
	# This functions returns a list of hash reference with with
	# all popboxes in the domain
	if($DEBUG){
		print "DEBUG DATA: sub _retrieve_popboxes<BR>";
	}
	my @popboxes;

	if ($VPOPMAIL_AUTH eq 'cdb'){
		# First check for symbolic links
		return 0 if -l "$DOMAINS_PATH/$DOMAIN/vpasswd.cdb";

		# We'll define our users according to data in the vpasswd file
		my %popboxes;
		tie %popboxes,'CDB_File',"$DOMAINS_PATH/$DOMAIN/vpasswd.cdb" or return 0;

		# Sorting routine
		my @index;

		foreach(keys %popboxes) {
			push @index, $_;
		};
		@index = sort @index;

		my @data;
		# Fill list with a hash reference for each popbox
		my ($key, $value);
		foreach (@index){

			$key = $_;
			$value = $popboxes{$key};

			# CDB gives a colon separated string with 
			#the popbox info fields. Let's turn it into a hash
			@data = split /:/, $value;
			if($data[5] eq 'NOQUOTA'){ $data[5] = $MAX_QUOTA; }
			push @popboxes, {pw_name => $key, pw_gecos => $data[3], pw_shell => $data[5]}; 

		}
	}
	if ($VPOPMAIL_AUTH eq 'mysql'){

		my $dbh = DBI->connect("dbi:mysql:$VPOPMAIL_MYSQL_DB", $VPOPMAIL_MYSQL_USER, $VPOPMAIL_MYSQL_PASSWD);
		if($DEBUG){
			print "Retrieving mysql data for popboxes<BR>";
			if($dbh){
				print "Mysql connection OK<BR>";
			} else {
				print "Mysql connection failed!<BR>";
			}
		}

		# SQL query for retrieving log info
		my $sql = "SELECT pw_name, pw_gecos, pw_shell FROM $VPOPMAIL_MYSQL_TABLE WHERE pw_domain='$DOMAIN' ORDER BY pw_name";
		if ($DEBUG) {
			print "Mysql query:$sql<BR>\n";
		}

		my $sth = $dbh->prepare($sql);
		$sth->execute();

		while($_ = $sth->fetchrow_hashref){
			if ($DEBUG){
				print "Adding $_->{pw_name}<BR>\n";
			}
			push @popboxes, $_;
		}

		$dbh->disconnect();
	}

	return @popboxes;
}


