#!/usr/bin/env python3

# resource.setrlimit(resource.RLIMIT_NOFILE, (30000, 30000))

import resource
import distro

getdistro = distro.id()
getdistro = getdistro.replace("'", "")

soft, hard = resource.getrlimit(resource.RLIMIT_OFILE)

if getdistro == 'centos':
	print("Host OS is CentOS")
	print("Current Open File settings - Soft: %s, Hard: %s" % (soft, hard))
	if hard < 30000:
		resource.setrlimit(resource.RLIMIT_NOFILE, (30000, 30000))

else:
	# soft, hard = resource.getrlimit(resource.RLIMIT_OFILE)
	print("Current Open File settings - Soft: %s, Hard: %s" % (soft, hard))
	if hard < 30000:
		resource.setrlimit(resource.RLIMIT_OFILE, (soft, 30000))
	if soft < 30000:
		resource.setrlimit(resource.RLIMIT_OFILE, (30000, hard))


soft2, hard2 = resource.getrlimit(resource.RLIMIT_OFILE)
print("Current Open File settings after change - Soft: %s, Hard: %s" % (soft2, hard2))

if getdistro == 'centos':
	if soft2 == 30000:
		print("reverting soft Open files to original setting %d" % soft)
		resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
	if hard2 == 30000:
		print("reverting hard Open files to original setting %d" % hard)
		resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
	
	soft3, hard3 = resource.getrlimit(resource.RLIMIT_NOFILE)
else:
	if soft2 == 30000:
		print("reverting soft Open files to original setting %d" % soft)
		resource.setrlimit(resource.RLIMIT_OFILE, (soft, hard))
	if hard2 == 30000:
		print("reverting hard Open files to original setting %d" % hard)
		resource.setrlimit(resource.RLIMIT_OFILE, (soft, hard))
	
soft3, hard3 = resource.getrlimit(resource.RLIMIT_OFILE)
print("Reverting Open File settings - Soft: %s, Hard: %s" % (soft3, hard3))
