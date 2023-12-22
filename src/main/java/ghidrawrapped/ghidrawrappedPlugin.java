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
import java.awt.CardLayout;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Scanner;

import javax.imageio.ImageIO;
import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Transaction;
import ghidra.framework.model.TransactionListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.FixedSizeStack;
import resources.Icons;
import resources.ResourceManager;

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

	private String EVENT_FILEPATH = "Event Filepath";
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
		
		ToolOptions toolOptions = pluginTool.getOptions("ghidrawrapped");
		if (!Objects.isNull(toolOptions)) {
			toolOptions.registerOption(EVENT_FILEPATH, "", null,
					"Specifies the filename to read and write user events to.");
		}
		
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
	@Override
	public void readConfigState(SaveState saveState) {
		// TODO: Figure out how to permit users to specify a record file location in the Tool
		// configuration.
	    Msg.debug(this, "readConfigState() called");
	}

	@Override
	public void writeConfigState(SaveState saveState) {
	    Msg.debug(this, "writeConfigState() called");
	}
	
	@Override
	protected void prepareToSave(DomainObject dobj) {
		super.prepareToSave(dobj);
		
		ToolOptions toolOptions = pluginTool.getOptions("ghidrawrapped");
		String eventFileAsString = toolOptions.getString(EVENT_FILEPATH, EVENT_FILEPATH);
		
	    FileWriter myWriter = null;
		try {
			myWriter = new FileWriter(eventFileAsString);
		} catch (IOException e) {
	    	Msg.error(this, e.getMessage());
		}
		
		//File eventFile = toolOptions.getFile(EVENT_FILEPATH, null);
		
		// TODO: write to file
		Msg.debug(this, "prepareToSave: ");
		if (!Objects.isNull(eventFileAsString)) {
			Msg.debug(this,  "prepareToSave(s): " + eventFileAsString);
		}
		
		
		if (!Objects.isNull(myWriter)) {
			Msg.debug(this, "prepareToSave(w): ");
			
			while (!listener.undoStack.isEmpty()) {
				UserEvent event = listener.undoStack.pop();
				Msg.debug(this,  "prepareToSave: event - " + event.eventDescription);
				try {
					myWriter.write(event.eventDescription + "\n");
					myWriter.flush();
				} catch (IOException e) {
					Msg.error(this,  "prepareToSave(w): error - " + e.getMessage());
				}
			}
			
			try {
				myWriter.close();
			} catch (IOException e) {
				Msg.error(this,  "prepareToSave close: error - " + e.getMessage());
			}
		}

	}
	
	@Override
	protected void programActivated(Program p) {
		super.programActivated(p);
		
		provider.setProgram(p);
		
		program = p;
		program.addTransactionListener(listener);
	}
	
	class UserEvent {
		
		OffsetDateTime eventTime;
		String eventDescription;
		
		public UserEvent(String description) {
			eventTime = OffsetDateTime.now( ZoneOffset.UTC );
			eventDescription = description;			
		}
	}
	
	/**
	 * Listener applied to current Program which will record all undoable actions to a stack.
	 */
	class ListenerForProgramChanges implements TransactionListener {
		private static final int MAX_UNDO_REDO_SIZE = 50;
		
		public FixedSizeStack<UserEvent> undoStack = new FixedSizeStack<>(MAX_UNDO_REDO_SIZE);
		
		public ListenerForProgramChanges() {
		}
		
		@Override
		public void transactionStarted(DomainObjectAdapterDB domainObj, Transaction tx) {			
			if (Objects.isNull(tx)) {
				return;
			}
			
			String description = tx.getDescription();
			if (Objects.isNull(description)) {
				return;
			}
			
			Msg.debug(this, "transactionStarted: " + description);
			// FIXME: Some transactionStarted() calls do not have a corresponding transactionEnded()?
			UserEvent event = new UserEvent(description);
			undoStack.push(event);
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
			if (Objects.isNull(description)) {
				return;
			}
			
			Msg.debug(this, "transactionEnded: " + description);
			UserEvent event = new UserEvent(description);
			undoStack.push(event);
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
			if (Objects.isNull(description)) {
				return;
			}
			
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
			if (Objects.isNull(description)) {
				return;
			}
			
			Msg.debug(this, "undoRedoOccurred: " + description);
			
			// FIXME: This is an attempt to distinguish between undo and redo events
			int undoStackDepth = domainObj.getUndoStackDepth();
			if (undoStack.size() > undoStackDepth) {
				Msg.debug(this, "undo: " + description);
				
				undoStack.pop();
			} else {
				Msg.debug(this, "redo: " + description);
				
				UserEvent redoEvent = new UserEvent(description);
				undoStack.push(redoEvent);
			}

		}
		
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JFrame frame;
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
			// TODO: Create a Panel where a user may specify a "Start Date" and an "End Date" 
			//panel = new JPanel(new BorderLayout());
			
			frame = new JFrame("tabbed");
						
			String firstTabName = "first tab";
			String secondTabName = "second tab";
			
			JTabbedPane tabbedPane = new JTabbedPane();
			panel = new JPanel(new CardLayout());
			
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea), "first");
			setVisible(true);
			
			InputStream in = ResourceManager.getResourceAsStream("images/Author.png");
			if (Objects.isNull(in)) {
				Msg.error(this,  "resource returned null!");
				return;
			}
			
			BufferedImage myPicture = null;
			try {
				myPicture = ImageIO.read(in);
			} catch (IOException e) {
				Msg.error(this,  e);
			}
			if (Objects.isNull(myPicture)) {
				Msg.error(this,  "file read returned null!");
				return;
			}
			
			ImageIcon icon = new ImageIcon(myPicture);
			ImageIcon scaledIcon = ResourceManager.getScaledIcon(icon, 512, 512);
			
			JLabel picLabel = new JLabel(scaledIcon);
			
			tabbedPane.addTab(firstTabName, panel);
			tabbedPane.addTab(secondTabName, picLabel);
			
			frame.getContentPane().add(tabbedPane, BorderLayout.CENTER);
			frame.pack();
			frame.setVisible(true);
			
			//panel.add(frame);
			//panel.setVisible(true);
			
		}

		// TODO: Customize actions
		private void createActions() {
			// TODO: Modify button to read the recorded user events from disk and collect metrics.
			// TODO: Modify Panel to set new images and text based on the metrics collected.
			action = new DockingAction("Ghidra Retrospective", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
					
					ToolOptions toolOptions = dockingTool.getOptions("ghidrawrapped");
					if (Objects.isNull(toolOptions)) {
						return;
					}
					
					String eventFileAsString = toolOptions.getString("Event Filepath", "Event Filepath");
					
					// FIXME: Expected option type: FILE_TYPE, but was STRING_TYPE
					//File eventFile = toolOptions.getFile("Event Filepath", null);
					File eventFile = null;

					try {
						eventFile = new File(eventFileAsString);
						Scanner myReader = new Scanner(eventFile);
						while (myReader.hasNextLine()) {
							String data = myReader.nextLine();
							Msg.info(this, data);
						}
						myReader.close();
				    } catch (FileNotFoundException e) {
				    	Msg.error(this, e.getMessage());
				    }
					
					Msg.debug(this, "actionPerformed: ");
					if (!Objects.isNull(eventFileAsString)) {
						Msg.debug(this,  "actionPerformed(s): " + eventFileAsString);
					}
					
					if (!Objects.isNull(eventFile)) {
						Msg.debug(this, "actionPerformed: " + eventFile.getName());
					}
					
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
