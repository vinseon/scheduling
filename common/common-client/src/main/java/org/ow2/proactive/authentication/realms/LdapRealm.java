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

import javax.naming.AuthenticationNotSupportedException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.ldap.UnsupportedAuthenticationMechanismException;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.ldap.JndiLdapContextFactory;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author ActiveEon Team
 * @since 23/01/17
 *
 * This class simply combines features from  DefaultLdapRealm , AbstractLdapRealm, and ActiveDirectoryRealm Shiro's classes
 *
 */
public class LdapRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(LdapRealm.class);

    private static final String ROLE_NAMES_DELIMETER = ",";

    //The zero index currently means nothing, but could be utilized in the future for other substitution techniques.
    private static final String USERDN_SUBSTITUTION_TOKEN = "{0}";

    private String userDnPrefix;

    private String userDnSuffix;

    protected String principalSuffix = null;

    protected String searchBase = null;

    //SHIRO-115 - prevent potential code injection:
    protected String searchFilter = "(&(objectClass=*)(cn={0}))";

    private LdapContextFactory contextFactory = null;

    /**
     * Mapping from fully qualified active directory
     * group names (e.g. CN=Group,OU=Company,DC=MyDomain,DC=local)
     * as returned by the active directory LDAP server to role names.
     */
    private Map<String, String> groupRolesMap;

    /**
     * Default no-argument constructor that defaults the internal {@link LdapContextFactory} instance to a
     * {@link JndiLdapContextFactory}.
     */
    public LdapRealm() {
        //Credentials Matching is not necessary - the LDAP directory will do it automatically:
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
        //Any Object principal and Object credentials may be passed to the LDAP provider, so accept any token:
        setAuthenticationTokenClass(AuthenticationToken.class);
        this.contextFactory = new JndiLdapContextFactory();
    }

    /**
     * Returns the User DN prefix to use when building a runtime User DN value or {@code null} if no
     * {@link #getUserDnTemplate() userDnTemplate} has been configured.  If configured, this value is the text that
     * occurs before the {@link #USERDN_SUBSTITUTION_TOKEN} in the {@link #getUserDnTemplate() userDnTemplate} value.
     *
     * @return the the User DN prefix to use when building a runtime User DN value or {@code null} if no
     *         {@link #getUserDnTemplate() userDnTemplate} has been configured.
     */
    protected String getUserDnPrefix() {
        return userDnPrefix;
    }

    /**
     * Returns the User DN suffix to use when building a runtime User DN value.  or {@code null} if no
     * {@link #getUserDnTemplate() userDnTemplate} has been configured.  If configured, this value is the text that
     * occurs after the {@link #USERDN_SUBSTITUTION_TOKEN} in the {@link #getUserDnTemplate() userDnTemplate} value.
     *
     * @return the User DN suffix to use when building a runtime User DN value or {@code null} if no
     *         {@link #getUserDnTemplate() userDnTemplate} has been configured.
     */
    protected String getUserDnSuffix() {
        return userDnSuffix;
    }

    /**
     * Used when initializing the default {@link LdapContextFactory}.  This property is ignored if a custom
     * <tt>LdapContextFactory</tt> is specified.
     *
     * @param principalSuffix the suffix.
     */
    public void setPrincipalSuffix(String principalSuffix) {
        this.principalSuffix = principalSuffix;
    }

    /**
     * Used when initializing the default {@link LdapContextFactory}.  This property is ignored if a custom
     * <tt>LdapContextFactory</tt> is specified.
     *
     * @param searchBase the search base.
     */
    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }

    public void setSearchFilter(String searchFilter) {
        this.searchFilter = searchFilter;
    }

    /**
     * Sets the User Distinguished Name (DN) template to use when creating User DNs at runtime.  A User DN is an LDAP
     * fully-qualified unique user identifier which is required to establish a connection with the LDAP
     * directory to authenticate users and query for authorization information.
     * <h2>Usage</h2>
     * User DN formats are unique to the LDAP directory's schema, and each environment differs - you will need to
     * specify the format corresponding to your directory.  You do this by specifying the full User DN as normal, but
     * but you use a <b>{@code {0}}</b> placeholder token in the string representing the location where the
     * user's submitted principal (usually a username or uid) will be substituted at runtime.
     * <p/>
     * For example,  if your directory
     * uses an LDAP {@code uid} attribute to represent usernames, the User DN for the {@code jsmith} user may look like
     * this:
     * <p/>
     * <pre>uid=jsmith,ou=users,dc=mycompany,dc=com</pre>
     * <p/>
     * in which case you would set this property with the following template value:
     * <p/>
     * <pre>uid=<b>{0}</b>,ou=users,dc=mycompany,dc=com</pre>
     * <p/>
     * If no template is configured, the raw {@code AuthenticationToken}
     * {@link AuthenticationToken#getPrincipal() principal} will be used as the LDAP principal.  This is likely
     * incorrect as most LDAP directories expect a fully-qualified User DN as opposed to the raw uid or username.  So,
     * ensure you set this property to match your environment!
     *
     * @param template the User Distinguished Name template to use for runtime substitution
     * @throws IllegalArgumentException if the template is null, empty, or does not contain the
     *                                  {@code {0}} substitution token.
     * @see LdapContextFactory#getLdapContext(Object,Object)
     */
    public void setUserDnTemplate(String template) throws IllegalArgumentException {
        if (!StringUtils.hasText(template)) {
            String msg = "User DN template cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        int index = template.indexOf(USERDN_SUBSTITUTION_TOKEN);
        if (index < 0) {
            String msg = "User DN template must contain the '" + USERDN_SUBSTITUTION_TOKEN +
                         "' replacement token to understand where to " + "insert the runtime authentication principal.";
            throw new IllegalArgumentException(msg);
        }
        String prefix = template.substring(0, index);
        String suffix = template.substring(prefix.length() + USERDN_SUBSTITUTION_TOKEN.length());
        if (log.isDebugEnabled()) {
            log.debug("Determined user DN prefix [{}] and suffix [{}]", prefix, suffix);
        }
        this.userDnPrefix = prefix;
        this.userDnSuffix = suffix;
    }

    /**
     * Returns the User Distinguished Name (DN) template to use when creating User DNs at runtime - see the
     * {@link #setUserDnTemplate(String) setUserDnTemplate} JavaDoc for a full explanation.
     *
     * @return the User Distinguished Name (DN) template to use when creating User DNs at runtime.
     */
    public String getUserDnTemplate() {
        return getUserDn(USERDN_SUBSTITUTION_TOKEN);
    }

    /**
     * Returns the LDAP User Distinguished Name (DN) to use when acquiring an
     * {@link LdapContext LdapContext} from the {@link LdapContextFactory}.
     * <p/>
     * If the the {@link #getUserDnTemplate() userDnTemplate} property has been set, this implementation will construct
     * the User DN by substituting the specified {@code principal} into the configured template.  If the
     * {@link #getUserDnTemplate() userDnTemplate} has not been set, the method argument will be returned directly
     * (indicating that the submitted authentication token principal <em>is</em> the User DN).
     *
     * @param principal the principal to substitute into the configured {@link #getUserDnTemplate() userDnTemplate}.
     * @return the constructed User DN to use at runtime when acquiring an {@link LdapContext}.
     * @throws IllegalArgumentException if the method argument is null or empty
     * @throws IllegalStateException    if the {@link #getUserDnTemplate userDnTemplate} has not been set.
     * @see LdapContextFactory#getLdapContext(Object, Object)
     */
    protected String getUserDn(String principal) throws IllegalArgumentException, IllegalStateException {
        if (!StringUtils.hasText(principal)) {
            throw new IllegalArgumentException("User principal cannot be null or empty for User DN construction.");
        }
        String prefix = getUserDnPrefix();
        String suffix = getUserDnSuffix();
        if (prefix == null && suffix == null) {
            log.debug("userDnTemplate property has not been configured, indicating the submitted " +
                      "AuthenticationToken's principal is the same as the User DN.  Returning the method argument " +
                      "as is.");
            return principal;
        }

        int prefixLength = prefix != null ? prefix.length() : 0;
        int suffixLength = suffix != null ? suffix.length() : 0;
        StringBuilder sb = new StringBuilder(prefixLength + principal.length() + suffixLength);
        if (prefixLength > 0) {
            sb.append(prefix);
        }
        sb.append(principal);
        if (suffixLength > 0) {
            sb.append(suffix);
        }
        return sb.toString();
    }

    /**
     * Sets the LdapContextFactory instance used to acquire connections to the LDAP directory during authentication
     * attempts and authorization queries.  Unless specified otherwise, the default is a {@link JndiLdapContextFactory}
     * instance.
     *
     * @param contextFactory the LdapContextFactory instance used to acquire connections to the LDAP directory during
     *                       authentication attempts and authorization queries
     */
    @SuppressWarnings({ "UnusedDeclaration" })
    public void setContextFactory(LdapContextFactory contextFactory) {
        this.contextFactory = contextFactory;
    }

    /**
     * Returns the LdapContextFactory instance used to acquire connections to the LDAP directory during authentication
     * attempts and authorization queries.  Unless specified otherwise, the default is a {@link JndiLdapContextFactory}
     * instance.
     *
     * @return the LdapContextFactory instance used to acquire connections to the LDAP directory during
     *         authentication attempts and authorization queries
     */
    public LdapContextFactory getContextFactory() {
        return this.contextFactory;
    }

    /**
     * Delegates to {@link #queryForAuthenticationInfo(AuthenticationToken, LdapContextFactory)},
     * wrapping any {@link NamingException}s in a Shiro {@link AuthenticationException} to satisfy the parent method
     * signature.
     *
     * @param token the authentication token containing the user's principal and credentials.
     * @return the {@link AuthenticationInfo} acquired after a successful authentication attempt
     * @throws AuthenticationException if the authentication attempt fails or if a
     *                                 {@link NamingException} occurs.
     */
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = queryForAuthenticationInfo(token, getContextFactory());
        } catch (AuthenticationNotSupportedException e) {
            String msg = "Unsupported configured authentication mechanism";
            throw new UnsupportedAuthenticationMechanismException(msg, e);
        } catch (javax.naming.AuthenticationException e) {
            throw new AuthenticationException("LDAP authentication failed.", e);
        } catch (NamingException e) {
            String msg = "LDAP naming error while attempting to authenticate user.";
            throw new AuthenticationException(msg, e);
        }

        return info;
    }

    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        AuthorizationInfo info;
        try {
            info = queryForAuthorizationInfo(principals, getContextFactory());
        } catch (NamingException e) {
            String msg = "LDAP naming error while attempting to retrieve authorization for user [" + principals + "].";
            throw new AuthorizationException(msg, e);
        }

        return info;
    }

    /**
     * Returns the principal to use when creating the LDAP connection for an authentication attempt.
     * <p/>
     * This implementation uses a heuristic: it checks to see if the specified token's
     * {@link AuthenticationToken#getPrincipal() principal} is a {@code String}, and if so,
     * {@link #getUserDn(String) converts it} from what is
     * assumed to be a raw uid or username {@code String} into a User DN {@code String}.  Almost all LDAP directories
     * expect the authentication connection to present a User DN and not an unqualified username or uid.
     * <p/>
     * If the token's {@code principal} is not a String, it is assumed to already be in the format supported by the
     * underlying {@link LdapContextFactory} implementation and the raw principal is returned directly.
     *
     * @param token the {@link AuthenticationToken} submitted during the authentication process
     * @return the User DN or raw principal to use to acquire the LdapContext.
     * @see LdapContextFactory#getLdapContext(Object, Object)
     */
    protected Object getLdapPrincipal(AuthenticationToken token) {
        Object principal = token.getPrincipal();
        if (principal instanceof String) {
            String sPrincipal = (String) principal;
            return getUserDn(sPrincipal);
        }
        return principal;
    }

    /**
     * This implementation opens an LDAP connection using the token's
     * {@link #getLdapPrincipal(AuthenticationToken) discovered principal} and provided
     * {@link AuthenticationToken#getCredentials() credentials}.  If the connection opens successfully, the
     * authentication attempt is immediately considered successful and a new
     * {@link AuthenticationInfo} instance is
     * {@link #createAuthenticationInfo(AuthenticationToken, Object, Object, LdapContext) created}
     * and returned.  If the connection cannot be opened, either because LDAP authentication failed or some other
     * JNDI problem, an {@link NamingException} will be thrown.
     *
     * @param token              the submitted authentication token that triggered the authentication attempt.
     * @param ldapContextFactory factory used to retrieve LDAP connections.
     * @return an {@link AuthenticationInfo} instance representing the authenticated user's information.
     * @throws NamingException if any LDAP errors occur.
     */
    protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token,
            LdapContextFactory ldapContextFactory) throws NamingException {

        Object principal = token.getPrincipal();
        Object credentials = token.getCredentials();

        log.debug("Authenticating user '{}' through LDAP", principal);

        principal = getLdapPrincipal(token);

        LdapContext ctx = null;
        try {
            ctx = ldapContextFactory.getLdapContext(principal, credentials);
            //context was opened successfully, which means their credentials were valid.  Return the AuthenticationInfo:
            return createAuthenticationInfo(token, principal, credentials, ctx);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }

    /**
     * Returns the {@link AuthenticationInfo} resulting from a Subject's successful LDAP authentication attempt.
     * <p/>
     * This implementation ignores the {@code ldapPrincipal}, {@code ldapCredentials}, and the opened
     * {@code ldapContext} arguments and merely returns an {@code AuthenticationInfo} instance mirroring the
     * submitted token's principal and credentials.  This is acceptable because this method is only ever invoked after
     * a successful authentication attempt, which means the provided principal and credentials were correct, and can
     * be used directly to populate the (now verified) {@code AuthenticationInfo}.
     * <p/>
     * Subclasses however are free to override this method for more advanced construction logic.
     *
     * @param token           the submitted {@code AuthenticationToken} that resulted in a successful authentication
     * @param ldapPrincipal   the LDAP principal used when creating the LDAP connection.  Unlike the token's
     *                        {@link AuthenticationToken#getPrincipal() principal}, this value is usually a constructed
     *                        User DN and not a simple username or uid.  The exact value is depending on the
     *                        configured
     *                        <a href="http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html">
     *                        LDAP authentication mechanism</a> in use.
     * @param ldapCredentials the LDAP credentials used when creating the LDAP connection.
     * @param ldapContext     the LdapContext created that resulted in a successful authentication.  It can be used
     *                        further by subclasses for more complex operations.  It does not need to be closed -
     *                        it will be closed automatically after this method returns.
     * @return the {@link AuthenticationInfo} resulting from a Subject's successful LDAP authentication attempt.
     * @throws NamingException if there was any problem using the {@code LdapContext}
     */
    @SuppressWarnings({ "UnusedDeclaration" })
    protected AuthenticationInfo createAuthenticationInfo(AuthenticationToken token, Object ldapPrincipal,
            Object ldapCredentials, LdapContext ldapContext) throws NamingException {
        return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
    }

    public void setGroupRolesMap(Map<String, String> groupRolesMap) {
        this.groupRolesMap = groupRolesMap;
    }

    /**
     * Builds an {@link AuthorizationInfo} object by querying the active directory LDAP context for the
     * groups that a user is a member of.  The groups are then translated to role names by using the
     * configured {@link #groupRolesMap}.
     * <p/>
     * This implementation expects the <tt>principal</tt> argument to be a String username.
     * <p/>
     * Subclasses can override this method to determine authorization data (roles, permissions, etc) in a more
     * complex way.  Note that this default implementation does not support permissions, only roles.
     *
     * @param principals         the principal of the Subject whose account is being retrieved.
     * @param ldapContextFactory the factory used to create LDAP connections.
     * @return the AuthorizationInfo for the given Subject principal.
     * @throws NamingException if an error occurs when searching the LDAP server.
     */
    protected AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principals,
            LdapContextFactory ldapContextFactory) throws NamingException {

        String username = getAvailablePrincipal(principals).toString();

        // Perform context search
        LdapContext ldapContext = ldapContextFactory.getSystemLdapContext();

        Set<String> roleNames;

        try {
            roleNames = getRoleNamesForUser(username, ldapContext);
        } finally {
            LdapUtils.closeContext(ldapContext);
        }

        return buildAuthorizationInfo(roleNames);
    }

    protected AuthorizationInfo buildAuthorizationInfo(Set<String> roleNames) {
        return new SimpleAuthorizationInfo(roleNames);
    }

    protected Set<String> getRoleNamesForUser(String username, LdapContext ldapContext) throws NamingException {
        Set<String> roleNames;
        roleNames = new LinkedHashSet<String>();

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        //Specify the attributes to return
        String returnedAtts[] = { "memberOf" };
        searchCtls.setReturningAttributes(returnedAtts);

        String userPrincipalName = username;
        if (principalSuffix != null) {
            userPrincipalName += principalSuffix;
        }

        Object[] searchArguments = new Object[] { userPrincipalName };

        NamingEnumeration answer = ldapContext.search(searchBase, searchFilter, searchArguments, searchCtls);

        while (answer.hasMoreElements()) {
            SearchResult sr = (SearchResult) answer.next();

            if (log.isDebugEnabled()) {
                log.debug("Retrieving group names for user [" + sr.getName() + "]");
            }

            Attributes attrs = sr.getAttributes();

            if (attrs != null) {
                NamingEnumeration ae = attrs.getAll();
                while (ae.hasMore()) {
                    Attribute attr = (Attribute) ae.next();

                    if (attr.getID().equals("memberOf")) {

                        Collection<String> groupNames = LdapUtils.getAllAttributeValues(attr);

                        if (log.isDebugEnabled()) {
                            log.debug("Groups found for user [" + username + "]: " + groupNames);
                        }

                        Collection<String> rolesForGroups = getRoleNamesForGroups(groupNames);
                        roleNames.addAll(rolesForGroups);
                    }
                }
            }
        }
        return roleNames;
    }

    /**
     * This method is called by the default implementation to translate Active Directory group names
     * to role names.  This implementation uses the {@link #groupRolesMap} to map group names to role names.
     *
     * @param groupNames the group names that apply to the current user.
     * @return a collection of roles that are implied by the given role names.
     */
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
}
