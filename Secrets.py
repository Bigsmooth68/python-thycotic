class Secrets:
    #SecretsSite = 'https://secretserver.cid.dom/SecretServer' # URL of secrets server
    SecretsAuthApi = '/oauth2/token' # Authentication token api
    SecretsAPI = '/api/v1' # Secrets api
    authTokens = None # To keep authentication token
    AccessDenied = False # store if access was denied
    cache = {} # local cache object
    getKeyFunction = None # function that return key based on hostname. It is also a parameter

    def __init__(self, site: str, SecretUser: str, SecretPassword: str, pKeyFunction: object):
        self.getKeyFunction = pKeyFunction

        if SecretPassword is None or len(SecretPassword) == 0:
            raise RestAuthenticationException

        self.SecretsSite = site
        self.SecretsAuthApi = site + self.SecretsAuthApi
        self.SecretsAPI = site + self.SecretsAPI

        # Prepare query to token API
        lCredentials = {}
        lCredentials['username'] = SecretUser
        lCredentials['password'] = SecretPassword
        lCredentials['grant_type'] = 'password'
        headers = {'Accept':'application/json', 'content-type':'application/x-www-form-urlencoded'}
        # Authenticate to Secret Server        
        response = requests.post(self.SecretsAuthApi, data=lCredentials, headers=headers)

        if response.status_code == 400: # Common error code from thycotic secrets server
            self.AccessDenied = True
            raise RestAuthenticationException(self.SecretsSite + ' cannot be reached. Invalid credentials(' + SecretUser + '/$SecretPassword).')

        self.authTokens = response.json()["access_token"] # Save it in object

    # Retrieves the secret item by its "slug" value
    def getItemBySlug(self, secretItems, slug):
        for x in secretItems['items']:
            if x['slug'] == slug:
                return x
        raise Exception('Item not found for slug: %s' % slug)

    # Retrieve Elastic Search UI credentials to query status, version, ...
    def getCredentials(self, host: str):
        lKey = self.getKeyFunction(host)

        if lKey in self.cache: # if already in cache returns it
            return self.cache[lKey]

        headers = {'Authorization':'Bearer ' + self.authTokens, 'content-type':'application/json'}
        try:
            resp = requests.get(self.SecretsAPI + '/secrets/' + str(lKey), headers=headers)
        except Exception as e:
            print(e)

        if resp.status_code not in (200, 304):
            print('error')
            raise Exception("Error retrieving Secret. %s %s" % (resp.status_code, resp))    

        try:
            lSecret = resp.json()
            lUser = self.getItemBySlug(lSecret,'username')['itemValue']
            lPassword = self.getItemBySlug(lSecret,'password')['itemValue']
        except Exception as e:
            print(e)

        # store in class cache
        self.cache[lKey] = (lUser, lPassword)
        return (lUser,lPassword)

class RestAuthenticationException(Exception):
    pass   
