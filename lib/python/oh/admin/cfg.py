
#
# Copyright 2004 OpenHosting, Inc.
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

# $Id: cfg.py,v 1.1 2004/12/24 03:26:17 grisha Exp $

def load_file(path):
    """Load a config file"""

    locals = {}

    try:
        execfile(path, {}, locals)
    except IOError, err:
        if 'No such file' in str(err):
            # no file is OK
            pass
        else:
            raise sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]

    return locals


from oh.common.cfg import *
from dft import *

locals().update(load_file(CONFIG_FILE))

