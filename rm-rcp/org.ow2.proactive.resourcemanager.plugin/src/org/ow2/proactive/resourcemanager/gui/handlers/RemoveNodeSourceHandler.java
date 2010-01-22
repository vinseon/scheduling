/*
 * ################################################################
 *
 * ProActive: The Java(TM) library for Parallel, Distributed,
 *            Concurrent computing with Security and Mobility
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
 *  Contributor(s): ActiveEon Team - http://www.activeeon.com
 *
 * ################################################################
 * $$ACTIVEEON_CONTRIBUTOR$$
 */
package org.ow2.proactive.resourcemanager.gui.handlers;

import org.eclipse.core.commands.AbstractHandler;
import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.core.commands.ExecutionException;
import org.eclipse.core.commands.HandlerEvent;
import org.eclipse.core.commands.IHandler;
import org.eclipse.ui.handlers.HandlerUtil;
import org.ow2.proactive.resourcemanager.gui.data.RMStore;
import org.ow2.proactive.resourcemanager.gui.dialog.RemoveSourceDialog;


public class RemoveNodeSourceHandler extends AbstractHandler implements IHandler {

    private static RemoveNodeSourceHandler instance;
    boolean previousState = true;

    public RemoveNodeSourceHandler() {
        super();
        instance = this;
    }

    public static RemoveNodeSourceHandler getInstance() {
        return instance;
    }

    @Override
    public boolean isEnabled() {
        boolean state;
        if (RMStore.isConnected() && RMStore.getInstance().getModel().getSourcesNames(false).length > 0) {
            state = true;
        } else
            state = false;

        //hack for toolbar menu (bug?), force event throwing if state changed.
        // Otherwise command stills disabled in toolbar menu
        //No mood to implement callbacks to static field of my handlers
        //to RMStore, just do business code
        //and let RCP API manages buttons...
        if (previousState != state) {
            previousState = state;
            fireHandlerChanged(new HandlerEvent(this, true, false));
        }
        return state;
    }

    public Object execute(ExecutionEvent event) throws ExecutionException {
        RemoveSourceDialog.showDialog(HandlerUtil.getActiveWorkbenchWindowChecked(event).getShell());
        return null;
    }
}
