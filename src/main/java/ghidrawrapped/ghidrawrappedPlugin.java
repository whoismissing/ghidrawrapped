/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidrawrapped;

import java.awt.BorderLayout;
import java.util.Objects;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.UndoRedoKeeper;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Transaction;
import ghidra.framework.model.TransactionListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Inspired by Spotify Wrapped, track user modifications to a Program to
 * record metrics and generate a personalized review.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "GhidraWrapped",
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Record metrics and generate a personalized review of reverse engineering work.",
	description = "Record all undoable actions on save and generate a personalized review of reverse engineering work."
)
//@formatter:on
public class ghidrawrappedPlugin extends ProgramPlugin {

	MyProvider provider;
	Program program;
	PluginTool pluginTool;
	ConsoleService console;
	
	private ListenerForProgramChanges listener;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public ghidrawrappedPlugin(PluginTool tool) {
		super(tool, true, true);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);
		pluginTool = tool;

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
		
		listener = new ListenerForProgramChanges();
		
		console = pluginTool.getService(ConsoleService.class);
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
	@Override
	public void readConfigState(SaveState saveState) {
	    Msg.debug(this, "readConfigState() called");
	}

	@Override
	public void writeConfigState(SaveState saveState) {
	    Msg.debug(this, "writeConfigState() called");
	}
	
	@Override
	protected void prepareToSave(DomainObject dobj) {
		// TODO: write to file
		
		super.prepareToSave(dobj);
		Msg.debug(this, "prepareToSave: ");

	}
	
	@Override
	protected void programActivated(Program p) {
		super.programActivated(p);
		
		provider.setProgram(p);
		
		program = p;
		program.addTransactionListener(listener);
	}
	
	class ListenerForProgramChanges implements TransactionListener {
		private UndoRedoKeeper undoRedoKeeper;

		public ListenerForProgramChanges() {
			undoRedoKeeper = new UndoRedoKeeper();
		}
		
		@Override
		public void transactionStarted(DomainObjectAdapterDB domainObj, Transaction tx) {			
			if (Objects.isNull(tx)) {
				return;
			}
			
			String description = tx.getDescription();
			
			Msg.debug(this, "transactionStarted: " + description);
			
		}

		@Override
		public void transactionEnded(DomainObjectAdapterDB domainObj) {
			if (Objects.isNull(domainObj)) {
				return;
			}
						
			Transaction tx = domainObj.getCurrentTransaction();
			
			if (Objects.isNull(tx)) {
				return;
			}
			
			String description = tx.getDescription();
			
			Msg.debug(this, "transactionEnded: " + description);
		}

		@Override
		public void undoStackChanged(DomainObjectAdapterDB domainObj) {			
			if (Objects.isNull(domainObj)) {
				return;
			}
			
			Transaction tx = domainObj.getCurrentTransaction();
			
			if (Objects.isNull(tx)) {
				return;
			}
			
			String description = tx.getDescription();
			Msg.debug(this, "undoStackChanged: " + description);
		}

		@Override
		public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {			
			if (Objects.isNull(domainObj)) {
				return;
			}
			
			Transaction tx = domainObj.getCurrentTransaction();
			
			if (Objects.isNull(tx)) {
				return;
			}
			
			String description = tx.getDescription();
			Msg.debug(this, "undoRedoOccurred: " + description);
		}
		
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;
		Program program;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			buildPanel();
			createActions();
		}

		public void setProgram(Program p) {
			// TODO Auto-generated method stub
			program = p;
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea));
			setVisible(true);
		}

		// TODO: Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
