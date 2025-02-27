// Import selected Overlays from a specified folder
//@author ThirstyWraith
//@author acemon33

import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.awt.*;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;


public class OverlaysImporter extends GhidraScript {

    @Override
    protected void run() throws Exception {
        File selectedFolder = askDirectory("Select a Folder", "Choose a folder contained Overlays:");
		if (selectedFolder != null && selectedFolder.isDirectory()) {
			List<JCheckBox> checkBoxes = createFileCheckBoxes(selectedFolder);

			JPanel panel = createPanel(checkBoxes);

			JButton okButton = new JButton("OK");
			okButton.setEnabled(false);
			
			JTextField addressField = setAddressFieldValidation(panel, okButton);
			
			showDialog(panel, okButton, addressField, selectedFolder, checkBoxes);

			println("finish");
        }
    }
	
	private List<JCheckBox> createFileCheckBoxes(File selectedFolder) {
		File[] files = selectedFolder.listFiles();
		List<JCheckBox> checkBoxes = new ArrayList<>();
		for (File file : files) {
			if (file.isFile()) {
				JCheckBox checkBox = new JCheckBox(file.getName());
				checkBoxes.add(checkBox);
			}
		}
		return checkBoxes;
	}
	
	private JPanel createPanel(List<JCheckBox> checkBoxes) {
		JPanel panel = new JPanel(new BorderLayout());
			
		JCheckBox selectAllCheckBox = new JCheckBox("Select All");
		selectAllCheckBox.addItemListener(e -> {
			boolean isSelected = selectAllCheckBox.isSelected();
			for (JCheckBox checkBox : checkBoxes) {
				checkBox.setSelected(isSelected);
			}
		});
		panel.add(selectAllCheckBox, BorderLayout.NORTH);

		JPanel checkBoxPanel = new JPanel(new GridLayout(0, 1));
		for (JCheckBox checkBox : checkBoxes) {
			checkBoxPanel.add(checkBox);
		}
		JScrollPane scrollPane = new JScrollPane(checkBoxPanel);
		panel.add(scrollPane, BorderLayout.CENTER);

		JPanel addressPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JLabel addressLabel = new JLabel("Enter Address:");
		JTextField addressField = new JTextField(20);
		addressPanel.add(addressLabel);
		addressPanel.add(addressField);
		panel.add(addressPanel, BorderLayout.SOUTH);
		
		return panel;
	}
	
	private JTextField setAddressFieldValidation(JPanel panel, JButton okButton) {
        JTextField addressField = (JTextField) ((JPanel) panel.getComponent(2)).getComponent(1);
		addressField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				validateAddress();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				validateAddress();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				validateAddress();
			}

			private void validateAddress() {
				String addressText = addressField.getText().trim();
				try {
					Address address = currentProgram.getAddressFactory().getAddress(addressText);
					okButton.setEnabled(address != null && currentProgram.getMemory().contains(address));
				} catch (Exception ex) {
					okButton.setEnabled(false);
				}
			}
		});
		return addressField;
	}

	private void showDialog(JPanel panel, JButton okButton, JTextField addressField, File selectedFolder, List<JCheckBox> checkBoxes) {
		Object[] options = { okButton, "Cancel" };
		JOptionPane optionPane = new JOptionPane(panel, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION, null, options, options[1]);
		JDialog dialog = optionPane.createDialog("Select Files and Enter Address");
		okButton.addActionListener(e -> {
			try {
				Address bassAddress = currentProgram.getAddressFactory().getAddress(addressField.getText().trim());
				Memory memory = currentProgram.getMemory();
				
				for (JCheckBox checkBox : checkBoxes) {
					if (checkBox.isSelected()) {
						File file = new File(selectedFolder.getAbsolutePath() + "/" + checkBox.getText());
						String blockName = getBlockName(file.getName());

						FileInputStream fileInputStream = new FileInputStream(file);
						byte[] fileData = new byte[(int) file.length()];
						fileInputStream.read(fileData);
						fileInputStream.close();

						ByteArrayInputStream inputStream = new ByteArrayInputStream(fileData);
						MemoryBlock block = memory.createInitializedBlock(blockName, bassAddress, inputStream, file.length(), monitor, true);
						block.setRead(true);
						block.setWrite(true);
						block.setExecute(true);
						println(String.format("Added %s as overlay block at %s", blockName, bassAddress));
					}
				}
			} catch (Exception ex) {
				println("Invalid address format: " + ex.getMessage());
			}
			dialog.dispose();
		});
		dialog.setVisible(true);
	}
	
	private String getBlockName(String fileName) {
        int lastDotIndex = fileName.lastIndexOf('.');
        return lastDotIndex != -1 ? fileName.substring(0, lastDotIndex) : fileName;
    }

}
