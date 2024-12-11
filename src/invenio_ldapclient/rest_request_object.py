class Kwarg_Request_Obj(object):
    def __init__(self, kwargs):
        self.kwargs = kwargs

    def get_username(self):
        return self.kwargs['username']

    def get_password(self):
        return self.kwargs['password']

    def set_email(self, email):
        self.kwargs['email'] = email

    def handle_no_users(self):
        self.kwargs['response_msg'] = 'No users REST msg'
        self.kwargs['response_code'] = ''

    def handle_dup_users(self):
        self.kwargs['response_msg'] = 'Dup users REST msg'
        self.kwargs['response_code'] = ''
    
    def handle_passwd_invalid(self):
        self.kwargs['response_msg'] = 'PwdInval REST msg'
        self.kwargs['response_code'] = ''

    def handle_no_email(self):
        self.kwargs['response_msg'] = 'No email REST msg'
        self.kwargs['response_code'] = ''

    def handle_access_not_permitted(self):
        self.kwargs['response_msg'] = 'Access not permitted REST msg'
        self.kwargs['response_code'] = ''
