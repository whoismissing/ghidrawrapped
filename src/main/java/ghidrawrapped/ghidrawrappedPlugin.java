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
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Graphics;
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
import java.util.HashMap;
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

	GhidraWrappedProvider provider;
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
		pluginTool = tool;

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new GhidraWrappedProvider(this, pluginName);

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
	protected void prepareToSave(DomainObject dobj) {
		super.prepareToSave(dobj);
		
		ToolOptions toolOptions = pluginTool.getOptions("ghidrawrapped");
		String eventFileAsString = toolOptions.getString(EVENT_FILEPATH, EVENT_FILEPATH);
		
		// FIXME: Persist tool option as a File object instead of converting from a string
		//File eventFile = toolOptions.getFile(EVENT_FILEPATH, null);
		
	    FileWriter myWriter = null;
		try {
			myWriter = new FileWriter(eventFileAsString);
		} catch (IOException e) {
	    	Msg.error(this, e.getMessage());
		}
		
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
				
		program = p;
		program.addTransactionListener(listener);
	}
	
	/**
	 * Record of a user interaction with the disassembler framework
	 */
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
	private static class GhidraWrappedProvider extends ComponentProvider {

		private JPanel mainPanel;
		private JLabel renamePanel;
		private JLabel structPanel;
		private JLabel graphicPanel;
		private JTextField renameText;
		private JTextField structText;
		private JTextField graphicText;
		private JLabel picLabel;
		private JTabbedPane tabbedPane;
		private DockingAction action;
		
		private HashMap<String, Integer> eventMap;
		
		public GhidraWrappedProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			
			plugin.getTool().addComponentProvider(this, false);
			
			buildPanel();
			createActions();
			
			eventMap = new HashMap<String, Integer>();
			eventMap.put("RENAME", new Integer(0));
			eventMap.put("STRUCTURE", new Integer(0));
			eventMap.put("GRAPHICAL", new Integer(0));
		}
		
		private JLabel getFrame(String frameName) {
			InputStream in = null;			
			in = ResourceManager.getResourceAsStream(frameName);
			
			BufferedImage myPicture = null;
			try {
				myPicture = ImageIO.read(in);
			} catch (IOException e) {
				Msg.error(this, e);
			}
			if (Objects.isNull(myPicture)) {
				Msg.error(this,  "file read returned null!");
				return null;
			}
			
			ImageIcon icon = new ImageIcon(myPicture);
			ImageIcon scaledIcon = ResourceManager.getScaledIcon(icon, 512, 512);
			JLabel pLabel = new JLabel(scaledIcon);
			return pLabel;
		}

		// Customize GUI
		private void buildPanel() {
			// TODO: Create a Panel where a user may specify a "Start Date" and an "End Date" 
			// TODO: Modify Panel to set new images and text based on the metrics collected.

			mainPanel = new JPanel(new CardLayout());
			renamePanel = getFrame("images/frame1.PNG");
			structPanel = getFrame("images/frame2.PNG");
			graphicPanel = getFrame("images/frame3.PNG");
			
			String firstTabName = "Rename Stats";
			String secondTabName = "Structure Stats";
			String thirdTabName = "Graphical Stats";
			tabbedPane = new JTabbedPane();
			
			tabbedPane.addTab(firstTabName, renamePanel);
			tabbedPane.addTab(secondTabName, structPanel);
			tabbedPane.addTab(thirdTabName, graphicPanel);
			mainPanel.add(tabbedPane);
			mainPanel.setVisible(true);
		}
		
		public boolean eventIsRename(String description) {
			if (description.contains("Edit Label")) {
				return true;
			} else if (description.contains("Rename Local Variable")) {
				return true;
			} else if (description.contains("Set Comments")) {
				return true;
			}
			return false;
		}
		
		public boolean eventIsStructure(String description) {
			if (description.contains("Edit Function")) {
				return true;
			} else if (description.contains("Create ")) {
				// Examples: "Create int" "Create dword"
				return true;
			} else if (description.contains("Retype Variable")) {
				return true;
			}
			return false;
		}
		
		public boolean eventIsGraphical(String description) {
			if (description.contains("Set Background Color")) {
				return true;
			}
			return false;
		}
		
		/**
		 * Increment the event count given an event category.
		 * @param event
		 */
		public void incrementEvent(String event) {
			if (event.contentEquals("RENAME") || event.contentEquals("STRUCTURE") || event.contentEquals("GRAPHICAL")) {
				Integer eventCount = eventMap.get(event);
				eventCount += 1;
				eventMap.put(event, eventCount);
			}
		}
		
		private void updatePanel() {
			if (Objects.isNull(renamePanel)) {
				return;
			}
			
			if (Objects.isNull(structPanel)) {
				return;
			}
			
			if (Objects.isNull(graphicPanel)) {
				return;
			}
			
			Integer renameCount = eventMap.get("RENAME");
			Integer structCount = eventMap.get("STRUCTURE");
			Integer graphicalCount = eventMap.get("GRAPHICAL");
			
			renameText = new JTextField(12);
			renamePanel.setText(renameCount.toString() + " Rename Events were observed");
			renamePanel.setHorizontalTextPosition(SwingConstants.CENTER);
			renamePanel.setFont(renameText.getFont().deriveFont(20f));
			renamePanel.setVisible(true);
			
			structText = new JTextField(12);
			structPanel.setText(structCount.toString() + " Struct Events were observed");
			structPanel.setHorizontalTextPosition(SwingConstants.CENTER);
			structPanel.setFont(structText.getFont().deriveFont(20f));
			structPanel.setVisible(true);
			
			graphicText = new JTextField(12);
			graphicPanel.setText(graphicalCount.toString() + " Graphic Events were observed");
			graphicPanel.setHorizontalTextPosition(SwingConstants.CENTER);
			graphicPanel.setFont(graphicText.getFont().deriveFont(20f));
			graphicPanel.setVisible(true);
			
			InputStream in = null;
			
			String wrappedText = "";
			if ((renameCount >= structCount) && (renameCount >= graphicalCount)) {
				in = ResourceManager.getResourceAsStream("images/Author.png");
				wrappedText = "You are an author!";
			} else if ((structCount >= renameCount) && (structCount >= graphicalCount)) {
				in = ResourceManager.getResourceAsStream("images/Architect.png");
				wrappedText = "You are an architect!";
			} else {
				in = ResourceManager.getResourceAsStream("images/Artist.png");
				wrappedText = "You are an artist!";
			}

			if (Objects.isNull(in)) {
				Msg.error(this,  "resource manager returned null!");
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
			picLabel = new JLabel(scaledIcon);
			picLabel.setText(wrappedText);
			picLabel.setHorizontalTextPosition(SwingConstants.CENTER);
			picLabel.setVerticalTextPosition(SwingConstants.BOTTOM);
			picLabel.setFont(graphicText.getFont().deriveFont(20f));
			String fourthTabName = "Your Wrapped";
			tabbedPane.addTab(fourthTabName, picLabel);
		}

		/**
		 * Create a button whose corresponding action will read the recorded user events from the configured event file path and record a summary of the results into the Provider
		 * which will display them in the panel.
		 */
		private void createActions() {
			action = new DockingAction("Ghidra Retrospective", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), mainPanel, "Summarize Results", "Processing your year in review...");
					
					ToolOptions toolOptions = dockingTool.getOptions("ghidrawrapped");
					if (Objects.isNull(toolOptions)) {
						return;
					}
					
					String eventFileAsString = toolOptions.getString("Event Filepath", "Event Filepath");
					if (Objects.isNull(eventFileAsString)) {
						return;
					}
					
					// FIXME: Expected option type: FILE_TYPE, but was STRING_TYPE
					// File eventFile = toolOptions.getFile("Event Filepath", null);
					File eventFile = null;

					try {
						eventFile = new File(eventFileAsString);
						Scanner myReader = new Scanner(eventFile);
						while (myReader.hasNextLine()) {
							String data = myReader.nextLine();
							Msg.info(this, data);
							
							if (eventIsRename(data)) {
								incrementEvent("RENAME");
							} else if (eventIsGraphical(data)) {
								incrementEvent("GRAPHICAL");
							} else if (eventIsStructure(data)) {
								incrementEvent("STRUCTURE");
							}
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
					
					updatePanel();
				}
			};
			
			if (Objects.isNull(action)) {
				Msg.error(this,  "createActions: action is null!");
				return;
			}
			
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			
			if (Objects.isNull(dockingTool)) {
				Msg.error(this,  "createActions: dockingTool is null!");
				return;
			}
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return mainPanel;
		}

	}
}
