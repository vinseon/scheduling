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
package org.ow2.proactive.authentication;

import java.io.File;
import java.security.KeyException;
import java.security.PublicKey;

import javax.security.auth.login.LoginException;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.objectweb.proactive.Body;
import org.objectweb.proactive.RunActive;
import org.objectweb.proactive.Service;
import org.objectweb.proactive.api.PAActiveObject;
import org.objectweb.proactive.core.body.request.Request;
import org.ow2.proactive.authentication.crypto.CredData;
import org.ow2.proactive.authentication.crypto.Credentials;


/**
 * An active object responsible for authentication.
 *
 * @author The ProActive Team
 * @since ProActive Scheduling 0.9.1
 */
public abstract class AuthenticationImpl implements Authentication, RunActive {

    // Shiro's security manager and current executing subject
    SecurityManager securityManager;
    Subject currentUser;

    /** Activation is used to control authentication during scheduling initialization */
    private boolean activated = false;

    /**
     * Defines login method
     * 
     * @return a string which represents the login method.
     */
    protected abstract String getLoginMethod();

    /**
     * Path to the private key file for used for authentication
     */
    protected String privateKeyPath;

    /**
     * Path to the private key file for used for authentication
     */
    protected String publicKeyPath;

    /**
     * Empty constructor
     */
    public AuthenticationImpl() {}

    /**
     * Default constructor
     * <p>
     * Loads jaas.config and stores it in global system property,
     * also locates keypair used for authentication:
     * public key is used to encrypt credentials to make the old deprecated API still compatible,
     * private key is used to decrypt credentials in the new API.
     * 
     * @param shiroPath path to the jaas configuration file
     * @param privPath path to the private key file
     * @param pubPath path to the public key file
     * 
     */
    public AuthenticationImpl(String shiroPath, String privPath, String pubPath) {
        File shiroFile = new File(shiroPath);
        if (shiroFile.exists() && !shiroFile.isDirectory()) {
            // Setup Shiro security manager from ini file
            Factory<SecurityManager> factory = new IniSecurityManagerFactory(shiroFile.getPath());
            securityManager = factory.getInstance();
            SecurityUtils.setSecurityManager(securityManager);

            // Get the currently executing user
            currentUser = SecurityUtils.getSubject();
        } else {
            throw new RuntimeException("Could not find Jaas configuration at: " + shiroPath);
        }

        File privFile = new File(privPath);
        if (privFile.exists() && !privFile.isDirectory()) {
            this.privateKeyPath = privPath;
        } else {
            throw new RuntimeException("Could not find private key file at: " + privPath);
        }

        File pubFile = new File(pubPath);
        if (pubFile.exists() && !pubFile.isDirectory()) {
            this.publicKeyPath = pubPath;
        } else {
            throw new RuntimeException("Could not find public key file at: " + pubPath);
        }
    }

    /**
     * Performs login.
     * 
     * @param cred encrypted username and password
     * @return the name of the user logged
     * @throws LoginException if username or password is incorrect.
     */
    public SerializableShiroSubjectWrapper authenticate(Credentials cred) throws AuthenticationException {

        if (activated == false) {
            throw new AuthenticationException("Authentication active object is not activated.");
        }

        if (!currentUser.isAuthenticated()) {

            CredData credentials = null;
            try {
                credentials = cred.decrypt(privateKeyPath);
            } catch (KeyException e) {
                throw new AuthenticationException("Could not decrypt credentials: " + e);
            }
            String username = credentials.getLogin();
            String password = credentials.getPassword();

            if (username == null || username.equals("")) {
                throw new AuthenticationException("Bad user name (user is null or empty)");
            }

            // TODO: check the login type (getLoginMethod()) and retrieve the desired Realm to authenticate with
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            token.setRememberMe(true);

            try {
                currentUser.login(token);
                getLogger().info("User [" + currentUser.getPrincipal() + "] logged in successfully.");
                return new SerializableShiroSubjectWrapper(currentUser);
            } catch (UnknownAccountException uae) {
                getLogger().info("There is no user with username of " + token.getPrincipal());
                throw new AuthenticationException("Authentication failed");
            } catch (IncorrectCredentialsException ice) {
                getLogger().info("Password for account " + token.getPrincipal() + " was incorrect!");
                throw new AuthenticationException("Authentication failed");
            } catch (LockedAccountException lae) {
                getLogger().info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
                throw new AuthenticationException("Authentication failed");
            }
            catch (Exception ae) {
                //unexpected condition?  error?
                throw new AuthenticationException("Authentication failed");
            }
        }
        else {
            return new SerializableShiroSubjectWrapper(currentUser);
        }
    }

    /**
     * Request this AuthenticationImpl's public key.
     * <p>
     * The public key provided by this method can be used to create encrypted credentials with
     * {@link org.ow2.proactive.authentication.crypto.Credentials#createCredentials(String, String, PublicKey)}.
     * The private key corresponding to this public key will be used for decryption.
     * 
     * @return this AuthenticationImpl's public key
     * @throws LoginException the key could not be retrieved
     */
    public PublicKey getPublicKey() throws LoginException {
        if (activated == false) {
            throw new LoginException("Authentication active object is not activated.");
        }
        try {
            return Credentials.getPublicKey(this.publicKeyPath);
        } catch (KeyException e) {
            getLogger().error("", e);
            throw new LoginException("Could not retrieve public key");
        }
    }

    /**
     * @see org.ow2.proactive.authentication.Authentication#isActivated()
     */
    public boolean isActivated() {
        return activated;
    }

    /**
     * Activates or desactivates authentication active object
     * 
     * @param activated the status of the desired activated state.
     */
    public void setActivated(boolean activated) {
        this.activated = activated;
    }

    /**
     * Terminates the active object
     * 
     * @return true if the object has been terminated.
     */
    public boolean terminate() {
        PAActiveObject.terminateActiveObject(false);
        getLogger().info("Authentication service is now shutdown!");
        return true;
    }

    /**
     * Method controls the execution of every request.
     * Tries to keep this active object alive in case of any exception.
     */
    public void runActivity(Body body) {
        Service service = new Service(body);
        while (body.isActive()) {
            Request request = null;
            try {
                request = service.blockingRemoveOldest();
                if (request != null) {
                    try {
                        service.serve(request);
                    } catch (Throwable e) {
                        getLogger().error("Cannot serve request: " + request, e);
                    }
                }
            } catch (InterruptedException e) {
                getLogger().warn("runActivity interrupted", e);
            }
        }
    }
}
