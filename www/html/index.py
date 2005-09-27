
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

from mod_python import apache

import base64

def _check_authen(req):

    if req.headers_in.has_key('Authorization'):

        try:
            s = req.headers_in['Authorization'][6:]
            s = base64.decodestring(s)
            user, passwd = s.split(":", 1)
        except:
            raise apache.SERVER_RETURN, apache.HTTP_BAD_REQUEST

        if user == cfg.WWW_USER and crypto.check_passwd_md5(passwd, cfg.WWW_PASSWD):
            return

    # if we got this far
    s = 'Basic realm="Access Restricted"'
    req.err_headers_out['WWW-Authenticate'] = s
    raise apache.SERVER_RETURN, apache.HTTP_UNAUTHORIZED


def index(req):

    _check_authen(req)

    return "More content will be added later\n"



        
    
                                                                                                                                                                                      
