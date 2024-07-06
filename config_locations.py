import re
import invenio_ldapclient
import importlib.resources
import os.path

def load_config(package = invenio_ldapclient.config):
    keys = []
    
    for k in dir(package):
        if k.startswith('LDAPCLIENT'):
            keys.append(k)

    return keys

if __name__ == '__main__':
    keys = load_config()
    outstr = ''

    for key in keys:
        outstr += key + '\n'

    print(outstr)
    

'''
def get_package_pyfiles(package = invenio_ldapclient, pyfiles = None):
    _pyfiles = pyfiles if pyfiles else []
    _files = importlib.resources.files(package).iterdir()
    for _file in _files:
        if _file.is_dir():
            get_package_pyfiles(_file, _pyfiles)
        else:
            if os.path(_file).endswith('.py'):
                pyfiles.append(_file)

    return _pyfiles
'''
    
            




#with open('invenio_ldapclient/views.py', 'r') as f:
#    for line in f:
        




