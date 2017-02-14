/*
 * ProActive Parallel Suite(TM):
 * The Open Source library for parallel and distributed
 * Workflows & Scheduling, Orchestration, Cloud Automation
 * and Big Data Analysis on Enterprise Grids & Clouds.
 *
 * Copyright (c) 2007 - 2017 ActiveEon
 * Contact: contact@activeeon.com
 *
 * This library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation: version 3 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * If needed, contact us to obtain a release under GPL Version 2 or 3
 * or a different license than the AGPL.
 */
package org.ow2.proactive.authentication.realms;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Unix-style <a href="http://www.kernel.org/pub/linux/libs/pam/index.html">PAM</a>
 * {@link org.apache.shiro.realm.Realm Realm} that uses <a href="https://github.com/kohsuke/libpam4j">libpam4j</a>
 * to interface with the PAM system libraries.
 * <p>
 * This is a single Shiro {@code Realm} that interfaces with the OS's {@code PAM} subsystem which itself
 * can be connected to several authentication methods (unix-crypt, LDAP, etc.)
 * <p>
 * This {@code Realm} can also take part in Shiro's Pluggable Realms concept.
 * <p>
 * Using a {@code PamRealm} requires a PAM {@code service} name. This is the name of the file under
 * {@code /etc/pam.d} that is used to initialise and configure the PAM subsytem. Normally, this file reflects
 * the application using it. For example {@code gdm}, {@code su}, etc. There is no default value for this propery.
 * <p>
 * For example, defining this realm in Shiro .ini:
 * <pre>
 * [main]
 * pamRealm = org.apache.shiro.realm.libpam4j.PamRealm
 * pamRealm.service = my-app
 * </pre>
 *
 * @author ActiveEon Team
 * @since 07/02/17
 */
public class PamRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(LdapRealm.class);

    private static final String ROLE_NAMES_DELIMETER = ",";

    private String service;

    private Map<String, String> groupRolesMap;

    public void setService(String service) {
        this.service = service;
    }

    public void setGroupRolesMap(Map<String, String> groupRolesMap) {
        this.groupRolesMap = groupRolesMap;
    }

    protected Collection<String> getRoleNamesForGroups(Collection<String> groupNames) {
        Set<String> roleNames = new HashSet<String>(groupNames.size());

        if (groupRolesMap != null) {
            for (String groupName : groupNames) {
                String strRoleNames = groupRolesMap.get(groupName);
                if (strRoleNames != null) {
                    for (String roleName : strRoleNames.split(ROLE_NAMES_DELIMETER)) {

                        if (log.isDebugEnabled()) {
                            log.debug("User is member of group [" + groupName + "] so adding role [" + roleName + "]");
                        }

                        roleNames.add(roleName);

                    }
                }
            }
        }
        return roleNames;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        Set<String> roles = new LinkedHashSet<String>();

        UnixUserPrincipal user = principals.oneByType(UnixUserPrincipal.class);
        if (user != null) {
            // Convert PAM groups to Shiro's roles
            roles.addAll(getRoleNamesForGroups(user.getUnixUser().getGroups()));
        }
        return new SimpleAuthorizationInfo(roles);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        UnixUser user;
        try {
            user = getPam().authenticate(upToken.getUsername(),
                    new String(upToken.getPassword()));
        } catch (PAMException e) {
            // Until libpam4j provides more details, we can only throw the top-level exception
            throw new AuthenticationException(e);
        }
        return new SimpleAuthenticationInfo(new UnixUserPrincipal(user), upToken.getPassword(),
                getName());
    }

    @Override
    protected void onInit() {
        super.onInit();
        try {
            // Tests PAM "connectivity"
            getPam();
        } catch (PAMException e) {
            throw new ShiroException("Cannot obtain PAM subsystem.", e);
        }
    }

    /**
     * Returns a {@code PAM} instance for the configured {@code service}.
     * <p>
     * Note that {@code PAM} instances are not reusable.
     *
     * @return an instance of {@code PAM} usable for authenticating users
     * @throws PAMException when something bad happens
     */
    protected PAM getPam() throws PAMException {
        // PAM instances are not reusable.
        return new PAM(service);
    }

    private static class UnixUserPrincipal {

        private final UnixUser unixUser;
        UnixUserPrincipal(UnixUser unixUser) {
            this.unixUser = unixUser;
        }

        public UnixUser getUnixUser() {
            return unixUser;
        }

        @Override
        public String toString() {
            return unixUser.getUserName() + ":" + unixUser.getUID();
        }
    }
}