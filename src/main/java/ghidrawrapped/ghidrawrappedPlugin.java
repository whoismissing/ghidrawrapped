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
		private JPanel renamePanel;
		private JPanel structPanel;
		private JPanel graphicPanel;
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

		// Customize GUI
		private void buildPanel() {
			// TODO: Create a Panel where a user may specify a "Start Date" and an "End Date" 
			// TODO: Modify Panel to set new images and text based on the metrics collected.

			mainPanel = new JPanel(new CardLayout());
			renamePanel = new JPanel(new BorderLayout());
			structPanel = new JPanel(new BorderLayout());
			graphicPanel = new JPanel(new BorderLayout());
			
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
			
			// TODO: Swap out counts in text
			class RenamePanel extends JPanel {
				@Override
			    public void paintComponent(Graphics g) {
			        super.paintComponent(g);
			        Color color = new Color(106, 0, 186, 1); // Purple
			        g.setColor(color);
			        g.drawRect(100, 10, 30, 40);
			    }

			    @Override
			    public Dimension getPreferredSize() {
			        return new Dimension(400,400);
			    }
			}
			renamePanel.add(new RenamePanel());
			renamePanel.setBackground(new Color(106, 0, 186, 1));
			renamePanel.setSize(512, 512);
			renamePanel.setVisible(true);
			
			class StructPanel extends JPanel {
				@Override
			    public void paintComponent(Graphics g) {
			        super.paintComponent(g);
			        Color color = new Color(18, 18, 18, 1); // Black
			        g.setColor(color);
			        g.drawRect(100, 10, 30, 40);
			    }

			    @Override
			    public Dimension getPreferredSize() {
			        return new Dimension(400,400);
			    }
			}
			structPanel.add(new StructPanel());
			structPanel.setBackground(new Color(18, 18, 18, 1));
			structPanel.setSize(512, 512);
			structPanel.setVisible(true);
			
			class GraphicPanel extends JPanel {
				@Override
			    public void paintComponent(Graphics g) {
			        super.paintComponent(g);
			        Color color = new Color(247, 116, 194, 1); // Pink
			        g.setColor(color);
			        g.drawRect(100, 10, 30, 40);
			    }

			    @Override
			    public Dimension getPreferredSize() {
			        return new Dimension(400,400);
			    }
			}
			graphicPanel.add(new GraphicPanel());
			graphicPanel.setBackground(new Color(247, 116, 194, 1));
			graphicPanel.setSize(512, 512);
			graphicPanel.setVisible(true);
			
			InputStream in = null;
			
			if ((renameCount >= structCount) && (renameCount >= graphicalCount)) {
				in = ResourceManager.getResourceAsStream("images/Author.png");
			} else if ((structCount >= renameCount) && (structCount >= graphicalCount)) {
				in = ResourceManager.getResourceAsStream("images/Architect.png");
			} else {
				in = ResourceManager.getResourceAsStream("images/Artist.png");
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
			JLabel picLabel = new JLabel(scaledIcon);
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
