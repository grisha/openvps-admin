
#
# Copyright 2005 OpenHosting, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from openvps.common import crypto
from openvps.admin import cfg
import RRD

from mod_python import apache

import os
import time
import tempfile

def __auth__(req, user, passwd):

    return (user == cfg.WWW_USER and
            crypto.check_passwd_md5(passwd, cfg.WWW_PASSWD))

def index(req):

    return "More content will be added later\n"

def _list_server_rrds():

    result = []

    files = os.listdir(cfg.VAR_DB_OPENVPS)

    for file in files:
        path = os.path.join(cfg.VAR_DB_OPENVPS, file)

        # make sure the file
        # * ends with '-uptime.rrd'
        # * it is a real file, not a link
        # * it has been updated in the past 24 hours
        if (not file.endswith('-uptime.rrd') or
            not os.path.isfile(path) or os.path.islink(path) or
            (time.time() - os.path.getmtime(path)) > 24*60*60):
            continue

        result.append(path)

    return result

def uptime(req, s='-2592000'): # 30 days

    args = ['/dev/null', '--start', s]

    rrds = _list_server_rrds()

    # list of rrds, each like
    # 'DEF:s0=/var/db/openvps/iad01-06-04-01.openvps.net-uptime.rrd:admin_uptime:AVERAGE',

    for n in xrange(len(rrds)):
        args.append('DEF:s%d=%s:admin_uptime:AVERAGE' % (n, rrds[n]))

    # now the tricky part - construct sum in RPN
    #'CDEF:avg=s0,s1,+,s2,+,s3,+,s4,+,s5,+,s6,+,s7,+,8,/',

    rpn = ['s0']
    for n in xrange(1, len(rrds)):
        rpn.append('s%d' % n)
        rpn.append('+')
    rpn.append('%d' % len(rrds))
    rpn.append('/')

    args.append('CDEF:avg=' + (','.join(rpn)))
    
    # the average
    args.append('VDEF:tot_avg=avg,AVERAGE')

    # the output
    args.append('PRINT:tot_avg:"average uptime\\: %9.6lf"')

    uptime = RRD.graph(*args)[2][0][1:-1]

    return uptime
 
def uptime_graph(req, s='-2592000'): # 30 days

    # generate a temporary path
    tfile, tpath = tempfile.mkstemp('.png', 'ova')
    os.close(tfile)

    args = [tpath, '--start', s, '--imgformat=PNG', '--width=600',
            '--base=1000', '--height=120', '--interlaced',
            '--lower-limi', '80',
            '--upper-limit', '101', '--rigid']

    rrds = _list_server_rrds()

    # list of rrds, each like
    # 'DEF:s0=/var/db/openvps/iad01-06-04-01.openvps.net-uptime.rrd:admin_uptime:AVERAGE',

    for n in xrange(len(rrds)):
        args.append('DEF:s%d=%s:admin_uptime:AVERAGE' % (n, rrds[n]))

    # now the tricky part - construct sum in RPN
    #'CDEF:avg=s0,s1,+,s2,+,s3,+,s4,+,s5,+,s6,+,s7,+,8,/',

    rpn = ['s0']
    for n in xrange(1, len(rrds)):
        rpn.append('s%d' % n)
        rpn.append('+')
    rpn.append('%d' % len(rrds))
    rpn.append('/')

    args.append('CDEF:avg=' + (','.join(rpn)))
    
    # the average
    args.append('VDEF:tot_avg=avg,AVERAGE')

    trend = 60*60*24*7 # 7 days

    # trended average
    args.append('CDEF:tavg=avg,%d,TREND' % trend)

    degr = '99.99'
    
    # degraded - anything less than 99.99%
    args.append('CDEF:degr=avg,%s,GE,0,INF,IF' % degr)
    
    # degraded shade
    args.append('AREA:degr#ffff99:degraded (less than %s)\\n' % degr)

    # tranded average
    args.append('LINE2:tavg#0000FF:%d day moving average\\n' % (trend / (60*60*24)))
                
    # real uptime
    args.append('LINE:avg#00FF00:simple average\\n')
                
    # the output
    args.append('COMMENT:\\n')
    args.append('GPRINT:tot_avg:Last %d Day Average\\: %%9.6lf\\n' % (abs(int(s)) / (60*60*24)))

    # run it
    RRD.graph(*args)

    req.content_type = 'image/png'
    req.sendfile(tpath)
    os.unlink(tpath)
                            
    return 
 

        
    
                                                                                                                                                                                      
