/*
 * ################################################################
 *
 * ProActive: The Java(TM) library for Parallel, Distributed,
 *            Concurrent computing with Security and Mobility
 *
 * Copyright (C) 1997-2008 INRIA/University of Nice-Sophia Antipolis
 * Contact: proactive@ow2.org
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or any later version.
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
 *  Initial developer(s):               The ProActive Team
 *                        http://proactive.inria.fr/team_members.htm
 *  Contributor(s):
 *
 * ################################################################
 * $$PROACTIVE_INITIAL_DEV$$
 */
package org.ow2.proactive.resourcemanager.common.scripting;

import java.io.File;
import java.io.Reader;
import java.io.StringReader;
import java.net.URL;

import javax.script.Bindings;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import org.objectweb.proactive.annotation.PublicAPI;


/**
 * This script can return the command that have to be executed as Task.
 * @see org.ow2.proactive.scheduler.task.NativeExecutable
 * @author The ProActive Team
 * @since 3.9
 */
@PublicAPI
public class GenerationScript extends Script<String> {

    /**
     * The variable name which must be set after the evaluation
     * of a verifying script.
     */
    public static final String RESULT_VARIABLE = "command";

    /**
     * Default value for GenerationScript return value
     */
    public static final String DEFAULT_COMMAND_VALUE = "NO COMMAND";

    /** ProActive needed constructor */
    public GenerationScript() {
    }

    /** Constructor that set the script.
     * @param script
     * @throws InvalidScriptException
     */
    public GenerationScript(Script<?> script) throws InvalidScriptException {
        super(script);
    }

    /** Constructor. Directly create a script with a string.
     * @param script representing the source code of the script 
     * @param engineName engine name used to interpret the script.
     * @throws InvalidScriptException if the creation fails.
     */
    public GenerationScript(String script, String engineName) throws InvalidScriptException {
        super(script, engineName);
    }

    /** Create a script from a file.
     * @param file containing the source code
     * @param parameters scripts parameters (arguments) 
     * @throws InvalidScriptException if the creation fails.
     */
    public GenerationScript(File file, String[] parameters) throws InvalidScriptException {
        super(file, parameters);
    }

    /** Create a script from an URL.
     * @param url containing the source code
     * @param parameters scripts parameters (arguments)
     * @throws InvalidScriptException if the creation fails.
     */
    public GenerationScript(URL url, String[] parameters) throws InvalidScriptException {
        super(url, parameters);
    }

    /** Return the engine that can execute this script. 
     * @see org.ow2.proactive.resourcemanager.common.scripting.Script#getEngine()
     */
    @Override
    protected ScriptEngine getEngine() {
        return new ScriptEngineManager().getEngineByName(scriptEngine);
    }

    /** 
     * Return the script id
     * @see org.ow2.proactive.resourcemanager.common.scripting.Script#getId()
     */
    @Override
    public String getId() {
        return this.id;
    }

    /**
     * Return a stream's reader associated to this script.
     * @see org.ow2.proactive.resourcemanager.common.scripting.Script#getReader()
     */
    @Override
    protected Reader getReader() {
        return new StringReader(script);
    }

    /**
     * @see org.ow2.proactive.resourcemanager.common.scripting.Script#getResult(javax.script.Bindings)
     */
    @Override
    protected ScriptResult<String> getResult(Bindings bindings) {
        if (bindings.containsKey(RESULT_VARIABLE)) {
            Object result = bindings.get(RESULT_VARIABLE);

            if (result instanceof String) {
                return new ScriptResult<String>((String) result);
            } else {
                return new ScriptResult<String>(new Exception("Bad result format : awaited String, found " +
                    result.getClass().getName()));
            }
        } else {
            return new ScriptResult<String>(new Exception("No binding for key " + RESULT_VARIABLE));
        }
    }

    /**
     * Prepare the script's special bindings; string that represents the selected native command
     * to launch .
     * @see org.ow2.proactive.resourcemanager.common.scripting.Script#prepareSpecialBindings(javax.script.Bindings)
     */
    @Override
    protected void prepareSpecialBindings(Bindings bindings) {
        bindings.put(RESULT_VARIABLE, DEFAULT_COMMAND_VALUE);
    }
}
