/*
 * ################################################################
 *
 * ProActive Parallel Suite(TM): The Java(TM) library for
 *    Parallel, Distributed, Multi-Core Computing for
 *    Enterprise Grids & Clouds
 *
 * Copyright (C) 1997-2010 INRIA/University of
 * 				Nice-Sophia Antipolis/ActiveEon
 * Contact: proactive@ow2.org or contact@activeeon.com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 * USA
 *
 * If needed, contact us to obtain a release under GPL Version 2
 * or a different license than the GPL.
 *
 *  Initial developer(s):               The ActiveEon Team
 *                        http://www.activeeon.com/
 *  Contributor(s):
 *
 * ################################################################
 * $ACTIVEEON_INITIAL_DEV$
 */
package org.ow2.proactive.resourcemanager.nodesource.infrastructure;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

import org.objectweb.proactive.core.util.wrapper.BooleanWrapper;
import org.ow2.proactive.resourcemanager.nodesource.common.Configurable;
import org.ow2.proactive.utils.FileToBytesConverter;


/**
 * This class implements a wrapper for user defined BatchJobInfrastructure. You must provide
 * a class file and classname of a class that implements a {@link BatchJobInfrastructure}.
 */
public class GenericBatchJobInfrastructure extends BatchJobInfrastructure {

    @Configurable(description = "Fully qualified classname\nof the implementation")
    protected String implementationClassname;

    @Configurable(fileBrowser = true, description = "Absolute path to the\nclass file of the implementation")
    protected String implementationFile;

    // the actual implementation of the infrastructure
    private BatchJobInfrastructure implementation;

    @Override
    public BooleanWrapper configure(Object... parameters) {
        BooleanWrapper resSuper = super.configure(parameters);
        this.implementationClassname = parameters[10].toString();
        byte[] implemtationClassfile = (byte[]) parameters[11];

        // read the class file and create a BatchJobInfrastructure instance
        try {
            File f = File.createTempFile("BatchJobClass", "GENERATED");
            f.deleteOnExit();
            FileToBytesConverter.convertByteArrayToFile(implemtationClassfile, f);
            URLClassLoader cl = new URLClassLoader(new URL[] { f.toURL() }, this.getClass().getClassLoader());
            Class<? extends BatchJobInfrastructure> implementationClass = (Class<? extends BatchJobInfrastructure>) cl
                    .loadClass(this.implementationClassname);
            this.implementation = implementationClass.newInstance();
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("Class " + this.implementationClassname + " does not exist", e);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Implementation class file does not exist", e);
        } catch (InstantiationException e) {
            throw new IllegalArgumentException("Class " + this.implementationClassname + " cannot be loaded",
                e);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Class " + this.implementationClassname + " cannot be loaded",
                e);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot create temp file for class " +
                this.implementationClassname, e);
        }

        return resSuper.booleanValue() ? new BooleanWrapper(true) : new BooleanWrapper(false);
    }

    @Override
    protected String extractSubmitOutput(String output) {
        return implementation.extractSubmitOutput(output);
    }

    @Override
    protected String getBatchinJobSystemName() {
        return implementation.getBatchinJobSystemName();
    }

    @Override
    protected String getDeleteJobCommand() {
        return implementation.getDeleteJobCommand();
    }

    @Override
    protected String getSubmitJobCommand() {
        return implementation.getSubmitJobCommand();
    }

}
