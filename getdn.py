import ldap3
import sys

server = ldap3.Server(sys.argv[1] , get_info = ldap3.ALL, port =389, use_ssl = False)
connection = ldap3.Connection(server)
connection.bind()
print(server.info)
