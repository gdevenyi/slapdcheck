# -*- coding: utf-8 -*-
"""
Automatic tests for module slapdcheck.checkmk
"""

import os
import unittest

from ldap0.ldapobject import LDAPObject
from ldap0.test import SlapdTestCase

import slapdcheck.checkmk

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

LDIF_TEMPLATE = """dn: %(suffix)s
objectClass: organization
o: %(o)s

dn: %(rootdn)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: %(rootcn)s
userPassword: %(rootpw)s

dn: cn=user1,%(suffix)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: user1
userPassword: user1_pw

dn: cn=Foo2,%(suffix)s
objectClass: organizationalRole
cn: Foo2

dn: cn=Foo1,%(suffix)s
objectClass: organizationalRole
cn: Foo1

dn: cn=Foo3,%(suffix)s
objectClass: organizationalRole
cn: Foo3

dn: ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Foo5,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo5

dn: cn=Foo4,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo4

dn: cn=Foo7,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo7

dn: cn=Foo6,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo6

dn: ou=äöüÄÖUß,ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: äöüÄÖUß

"""


class TestCheckMk(SlapdTestCase):
    """
    test LDAP search operations
    """
    ldap_object_class = LDAPObject
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(Test00_LDAPObject, cls).setUpClass()
        # insert some Foo* objects via ldapadd
        cls.server.ldapadd(
            (LDIF_TEMPLATE % {
                'suffix':cls.server.suffix,
                'rootdn':cls.server.root_dn,
                'rootcn':cls.server.root_cn,
                'rootpw':cls.server.root_pw,
                'o': cls.server.suffix.split(',')[0][3:],
            }).encode('utf-8')
        )

    def setUp(self):
        try:
            self._ldap_conn
        except AttributeError:
            # open local LDAP connection
            self._ldap_conn = self._open_ldap_conn()


if __name__ == '__main__':
    unittest.main()
