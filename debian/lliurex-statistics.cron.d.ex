#
# Regular cron jobs for the lliurex-statistics package
#
0 4	* * *	root	[ -x /usr/bin/lliurex-statistics_maintenance ] && /usr/bin/lliurex-statistics_maintenance
