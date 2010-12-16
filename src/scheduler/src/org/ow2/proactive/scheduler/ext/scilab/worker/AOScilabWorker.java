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
 *  Initial developer(s):               The ProActive Team
 *                        http://proactive.inria.fr/team_members.htm
 *  Contributor(s):
 *
 * ################################################################
 * $$PROACTIVE_INITIAL_DEV$$
 */
package org.ow2.proactive.scheduler.ext.scilab.worker;

import javasci.SciData;
import javasci.Scilab;
import org.objectweb.proactive.api.PAActiveObject;
import org.ow2.proactive.scheduler.common.task.TaskResult;
import org.ow2.proactive.scheduler.ext.matsci.worker.MatSciWorker;
import org.ow2.proactive.scheduler.ext.scilab.common.PASolveScilabGlobalConfig;
import org.ow2.proactive.scheduler.ext.scilab.common.PASolveScilabTaskConfig;
import org.ow2.proactive.scheduler.ext.scilab.common.exception.InvalidParameterException;
import org.ow2.proactive.scheduler.ext.scilab.common.exception.ScilabInitializationException;
import org.ow2.proactive.scheduler.ext.scilab.common.exception.ScilabInitializationHanged;
import org.ow2.proactive.scheduler.ext.scilab.common.exception.ScilabTaskException;
import org.ow2.proactive.scheduler.ext.scilab.worker.util.ScilabEngineConfig;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * An active object which handles the interaction between the ScilabTask and a local Scilab engine
 * @author The ProActive Team
 */
public class AOScilabWorker implements Serializable, MatSciWorker {

    static String nl = System.getProperty("line.separator");

    /**
     * script executed to initialize the task (input parameter)
     */
    private String inputScript = null;

    /**
     * Output variables
     */
    private String[] outputVars = null;

    /**
     *  Main script to be executed
     */
    private ArrayList<String> mainscriptLines = new ArrayList<String>();

    /**
     * Configuration of Scilab (paths)
     */
    private ScilabEngineConfig config;

    private boolean initialized = false;
    private boolean initErrorOccured = false;
    private Throwable initError = null;

    /**
     * Definition of user-functions
     */
    private String functionsDefinition = null;
    private String functionName = null;

    private String nodeName = null;
    private File tmpDirNode = null;
    private PASolveScilabGlobalConfig paconfig = null;
    private PASolveScilabTaskConfig taskconfig;

    public AOScilabWorker() {
    }

    /**
     * Constructor for the Simple task
     *
     * @param scilabConfig the configuration for scilab
     */
    public AOScilabWorker(ScilabEngineConfig scilabConfig) throws Exception {
        this.config = scilabConfig;
    }

    private void initializeEngine() throws Exception {
        if (!initialized) {
            try {
                if (paconfig.isDebug()) {
                    System.out.println("Scilab Initialization...");
                    System.out.println("PATH=" + System.getenv("PATH"));
                    System.out.println("LD_LIBRARY_PATH=" + System.getenv("LD_LIBRARY_PATH"));
                    System.out.println("java.library.path=" + System.getProperty("java.library.path"));
                }
                System.out.println("Starting a new Scilab engine:");
                System.out.println(config);
                scilabStarter();

                if (paconfig.isDebug()) {
                    System.out.println("Initialization Complete!");
                }
            } catch (UnsatisfiedLinkError e) {
                StringWriter error_message = new StringWriter();
                PrintWriter pw = new PrintWriter(error_message);
                pw.println("Can't find the Scilab libraries in host " + java.net.InetAddress.getLocalHost());
                pw.println("PATH=" + System.getenv("PATH"));
                pw.println("LD_LIBRARY_PATH=" + System.getenv("LD_LIBRARY_PATH"));
                pw.println("java.library.path=" + System.getProperty("java.library.path"));

                ScilabInitializationException ne = new ScilabInitializationException(error_message.toString());
                ne.initCause(e);
                throw ne;
            } catch (NoClassDefFoundError e) {
                StringWriter error_message = new StringWriter();
                PrintWriter pw = new PrintWriter(error_message);
                pw.println("Classpath Error in " + java.net.InetAddress.getLocalHost());
                pw.println("java.class.path=" + System.getProperty("java.class.path"));

                ScilabInitializationException ne = new ScilabInitializationException(error_message.toString());
                ne.initCause(e);
                throw ne;
            } catch (ScilabInitializationException e) {
                throw e;
            } catch (Throwable e) {

                StringWriter error_message = new StringWriter();
                PrintWriter pw = new PrintWriter(error_message);
                pw.println("Error initializing Scilab in " + java.net.InetAddress.getLocalHost());
                pw.println("PATH=" + System.getenv("PATH"));
                pw.println("LD_LIBRARY_PATH=" + System.getenv("LD_LIBRARY_PATH"));
                pw.println("java.library.path=" + System.getProperty("java.library.path"));
                pw.println("java.class.path=" + System.getProperty("java.class.path"));

                IllegalStateException ne = new IllegalStateException(error_message.toString());
                ne.initCause(e);
                throw ne;
            }

            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
                public void run() {
                    Scilab.Finish();
                }
            }));

            nodeName = PAActiveObject.getNode().getVMInformation().getName().replace('-', '_');
            File tmpDir = new File(System.getProperty("java.io.tmpdir"));
            tmpDirNode = new File(tmpDir, nodeName);
            if (!tmpDirNode.exists() || !tmpDirNode.isDirectory()) {
                tmpDirNode.mkdir();
            }

            initialized = true;
        }

    }

    private void scilabStarter() throws Throwable {

        Runnable runner = new Runnable() {
            public void run() {
                try {
                    Scilab.init();
                    initialized = true;
                } catch (Throwable t) {
                    initError = t;
                    initErrorOccured = true;
                }
            }
        };

        Thread starter = new Thread(runner);
        starter.start();

        int nbwait = 0;
        while (!initialized && !initErrorOccured && nbwait < 200) {
            try {
                Thread.sleep(50);
                nbwait++;
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        if (initErrorOccured)
            throw initError;
        if (!initialized)
            throw new ScilabInitializationHanged(
                "Couldn't initialize the Scilab engine, this is due to a known bug in Scilab initialization");
    }

    public void init(String inputScript, String functionName, String functionsDefinition,
            ArrayList<String> scriptLines, String[] outputVars, PASolveScilabGlobalConfig paconfig,
            PASolveScilabTaskConfig taskconfig, ScilabEngineConfig conf) {
        if (!this.config.equals(conf)) {
            terminate();
        }
        this.config = conf;
        this.inputScript = inputScript;
        this.mainscriptLines = scriptLines;
        this.outputVars = outputVars;
        this.paconfig = paconfig;
        this.taskconfig = taskconfig;
        this.functionsDefinition = functionsDefinition;
        this.functionName = functionName;
    }

    public Serializable execute(int index, TaskResult... results) throws Throwable {

        initializeEngine();

        boolean ok = true;

        HashMap<String, List<SciData>> newEnv = new HashMap<String, List<SciData>>();

        if (results != null) {

            for (TaskResult res : results) {
                if (!(res.value() instanceof List)) {
                    throw new InvalidParameterException(res.value().getClass());
                }

                for (SciData in : (List<SciData>) res.value()) {
                    if (newEnv.containsKey(in.getName())) {
                        List<SciData> ldata = newEnv.get(in.getName());
                        ldata.add(in);
                    } else {
                        ArrayList<SciData> ldata = new ArrayList<SciData>();
                        ldata.add(in);
                        newEnv.put(in.getName(), ldata);
                    }

                    //Scilab.sendData(in);
                }
            }
        }

        for (Map.Entry<String, List<SciData>> entry : newEnv.entrySet()) {
            List<SciData> ldata = entry.getValue();
            int i = 1;
            for (SciData in : ldata) {
                in.setName(in.getName() + i);
                i++;
                Scilab.sendData(in);
            }
        }
        // Initialization, clearing up old variables :
        if (paconfig.isDebug()) {
            Scilab.Exec("errclear();clear;mode(3);lines(0);funcprot(0);");
        } else {
            Scilab.Exec("errclear();clear;mode(3);lines(0);funcprot(0);");
        }

        if (functionsDefinition != null) {
            ok = executeFunctionDefinition();
            if (!ok)
                throw new IllegalStateException("Error in function definitions");
        }

        if (inputScript != null) {
            if (paconfig.isDebug()) {
                System.out.println("[AOScilabWorker] Executing inputscript");
            }
            ok = executeScript(inputScript, false);
            if (paconfig.isDebug()) {
                System.out.println("[AOScilabWorker] End of inputscript execution");
            }
        }
        if (!ok)
            throw new IllegalStateException("Error executing inputscript");
        if (paconfig.isDebug()) {
            System.out.println("[AOScilabWorker] Executing mainscript");
        }
        ok = executeScript(prepareScript(mainscriptLines), true);
        if (paconfig.isDebug()) {
            System.out.println("[AOScilabWorker] End of mainscript execution " + (ok ? "ok" : "ko"));
        }

        if (!ok)
            throw new ScilabTaskException();

        return getResults(ok);

    }

    /**
     * Terminates the Scilab engine
     *
     * @return true for synchronous call
     */
    public boolean terminate() {
        Scilab.Finish();
        initialized = false;
        return true;
    }

    public boolean cleanup() {
        // Pack not yet supported on scilab
        return true;
    }

    /**
     * Loads in Scilab the user-functions definitions
     * 
     * @return success
     * @throws IOException
     */
    protected boolean executeFunctionDefinition() throws IOException {

        File functionFile = new File(tmpDirNode, functionName + ".sci");
        if (functionFile.exists()) {
            functionFile.delete();
        }
        functionFile.createNewFile();
        functionFile.deleteOnExit();

        BufferedWriter out = new BufferedWriter(new FileWriter(functionFile));
        out.write(functionsDefinition.replaceAll("" + ((char) 31), System.getProperty("line.separator")));
        out.close();
        if (paconfig.isDebug()) {
            System.out.println("[AOScilabWorker] Executing function definition : " +
                functionFile.getAbsolutePath());
            Scilab.Exec("exec('" + functionFile.getAbsolutePath() + "')");

        } else {
            Scilab.Exec("exec('" + functionFile.getAbsolutePath() + "');");
        }
        int errorcode = Scilab.GetLastErrorCode();
        if ((errorcode != 0) && (errorcode != 2)) {
            writeError();
            return false;
        }

        return true;
    }

    /**
     * Retrieves the output variables
     *
     * @return list of Scilab data
     */
    protected ArrayList<SciData> getResults(boolean error) {

        if (paconfig.isDebug()) {
            System.out.println("[AOScilabWorker] Receiving outputs");
        }
        ArrayList<SciData> out = new ArrayList<SciData>();
        int i = 0;
        for (String var : outputVars) {
            if (paconfig.isDebug()) {
                System.out.println("[AOScilabWorker] Receiving output :" + var);
            }
            if (Scilab.ExistVar(var)) {
                SciData output = Scilab.receiveDataByName(var);
                if (output == null) {
                    throw new IllegalStateException("Variable " + var +
                        " existing in scilab engine but couldn't be retrieved (this is a known bug in Scilab 5.2)");
                }
                if (paconfig.isDebug()) {
                    System.out.println(output);
                }
                out.add(output);
            } else {
                throw new IllegalStateException("Variable " + var + " not found");
            }
        }
        return out;

    }

    /**
     * Executes both input and main scripts on the engine
     *
     * @throws Throwable
     */
    protected boolean executeScript(String script, boolean eval) throws Throwable {

        if (eval) {

            if (script.indexOf(31) >= 0) {
                String[] lines = script.split("" + ((char) 31));
                if (paconfig.isDebug()) {
                    System.out.println("[AOScilabWorker] Executing multi-line: " + script);
                }
                for (String line : lines) {

                    // The special character ASCII 30 means that we want to execute the line using execstr instead of directly
                    // This is used to get clearer error messages from Scilab
                    if (line.startsWith("" + ((char) 30))) {
                        String modifiedLine = "execstr('" + line.substring(1) + "','errcatch','n');";
                        if (paconfig.isDebug()) {
                            System.out.println("[AOScilabWorker] Executing : " + modifiedLine);
                        }
                        Scilab.Exec(modifiedLine);
                        int errorcode = Scilab.GetLastErrorCode();
                        if ((errorcode != 0) && (errorcode != 2)) {
                            writeError();
                            return false;
                        }
                    } else {
                        if (paconfig.isDebug()) {
                            System.out.println("[AOScilabWorker] Executing : " + line);
                        }
                        Scilab.Exec(line);
                        int errorcode = Scilab.GetLastErrorCode();
                        if ((errorcode != 0) && (errorcode != 2)) {
                            writeError();
                            return false;
                        }
                    }
                }
            } else {
                if (paconfig.isDebug()) {
                    System.out.println("[AOScilabWorker] Executing single-line: " + script);
                }
                Scilab.Exec(script);
                int errorcode = Scilab.GetLastErrorCode();
                if ((errorcode != 0) && (errorcode != 2)) {
                    writeError();
                    return false;
                }
            }

        } else {
            File temp;
            BufferedWriter out;
            if (paconfig.isDebug()) {
                System.out.println("[AOScilabWorker] Executing inputscript: " + script);
            }
            temp = new File(tmpDirNode, "inpuscript.sce");
            if (temp.exists()) {
                temp.delete();
            }
            temp.createNewFile();
            temp.deleteOnExit();
            out = new BufferedWriter(new FileWriter(temp));
            out.write(script);
            out.close();
            if (paconfig.isDebug()) {
                Scilab.Exec("exec('" + temp.getAbsolutePath() + "',3);");
            } else {
                Scilab.Exec("exec('" + temp.getAbsolutePath() + "',0);");
            }
            int errorcode = Scilab.GetLastErrorCode();
            if ((errorcode != 0) && (errorcode != 2)) {
                Scilab.Exec("disp(lasterror())");
                Scilab.Exec("errclear();");
                return false;
            }
        }
        return true;
    }

    /**
     * Ouput in scilab the error occured
     */
    private void writeError() {

        Scilab
                .Exec("[str2,n2,line2,func2]=lasterror(%t);printf('!-- error %i\n%s\n at line %i of function %s\n',n2,str2,line2,func2)");

        Scilab.Exec("errclear();");
    }

    /**
     * Appends all the script's lines as a single string
     *
     * @return single line script
     */
    private String prepareScript(List<String> scriptLines) {
        String script = "";

        for (String line : scriptLines) {
            script += line;
            script += nl;
        }

        return script;
    }
}