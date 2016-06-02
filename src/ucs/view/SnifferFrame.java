/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ucs.view;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import cn.edu.shu.ipv6sniffer.control.Ipv6SnifferControl;

/**
 *
 * @author Alessandro A. Feitosa
 */
public class SnifferFrame extends javax.swing.JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7160835837632290482L;
	public static JFrame frame = new JFrame("Interactive Frame");
	private SnifferControl ipv6SnifferControl = new SnifferControl();

	/**
	 * Creates new form Ipv6SnifferFrame
	 */
	public SnifferFrame() {
		initComponents();
		//ipv6SnifferControl.setIpv6OnlyButton(ipv6OnlyButton);
		ipv6SnifferControl.setDetailPacketTree(detailPacketTree);
		ipv6SnifferControl.setNetworkInterface(networkInterface);
		ipv6SnifferControl.setPacketTable(packetTable);
		ipv6SnifferControl.setStartButton(startButton);
		ipv6SnifferControl.setStatsButton(statsButton);
		ipv6SnifferControl.setPacketTable(packetTable);
		ipv6SnifferControl.setTextArea(textArea);

		ipv6SnifferControl.initAllComponents();
	}

	/**
	 * This method is called from within the constructor to initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is always
	 * regenerated by the Form Editor.
	 */
	// <editor-fold defaultstate="collapsed"
	// desc="Generated Code">//GEN-BEGIN:initComponents
	private void initComponents() {

		jPanel1 = new javax.swing.JPanel();
		jLabel1 = new javax.swing.JLabel();
		networkInterface = new javax.swing.JComboBox<String>();
		jScrollPane1 = new javax.swing.JScrollPane();
		packetTable = new javax.swing.JTable();
		startButton = new javax.swing.JButton();
		statsButton = new javax.swing.JButton();
		jScrollPane2 = new javax.swing.JScrollPane();
		detailPacketTree = new javax.swing.JTree();
		textArea = new javax.swing.JTextArea();
		//ipv6OnlyButton = new javax.swing.JRadioButton();

		setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

		//jLabel1.setFont(new java.awt.Font("Times New Roman", 0, 18));
		jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel1.setText("Selecione um adaptador de rede para monitorar");

		//networkInterface.setFont(new java.awt.Font("Times New Roman", 0, 18));
		networkInterface.setModel(new javax.swing.DefaultComboBoxModel<String>());
		networkInterface.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				networkInterfaceActionPerformed(evt);
			}
		});

		packetTable.setModel(new javax.swing.table.DefaultTableModel() {
			/**
			 * 
			 */
			private static final long serialVersionUID = 616040251973729541L;
			boolean[] canEdit = new boolean[] { false, false, false, false };

			public boolean isCellEditable(int rowIndex, int columnIndex) {
				return canEdit[columnIndex];
			}
		});
		packetTable.getSelectionModel().addListSelectionListener(
				new ListSelectionListener() {
					public void valueChanged(ListSelectionEvent e) {
						// TODO Auto-generated method stub
						tableSelectActionPerformed(e);
					}
				});
		jScrollPane1.setViewportView(packetTable);

		startButton.setText("Start");
		startButton.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				startButtonActionPerformed(evt);
			}
		});
		
		statsButton.setText("Estatisticas");
		statsButton.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				statsButtonActionPerformed(evt);
			}
		});

		jScrollPane2.setViewportView(detailPacketTree);

		totalPanel = new JScrollPane (textArea, 
				   JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
		
		javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(
				jPanel1);
		jPanel1.setLayout(jPanel1Layout);
		jPanel1Layout
				.setHorizontalGroup(jPanel1Layout
						.createParallelGroup(
								javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(
								javax.swing.GroupLayout.Alignment.TRAILING,
								jPanel1Layout
										.createSequentialGroup()
										.addContainerGap()
										.addGroup(
												jPanel1Layout
														.createParallelGroup(
																javax.swing.GroupLayout.Alignment.TRAILING)
														.addComponent(
																totalPanel,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																Short.MAX_VALUE)
														.addComponent(
																jScrollPane2)
														.addComponent(
																jScrollPane1)
														.addGroup(
																jPanel1Layout
																		.createSequentialGroup()
																		.addComponent(
																				jLabel1,
																				javax.swing.GroupLayout.DEFAULT_SIZE,
																				100,
																				Short.MAX_VALUE)
																		.addComponent(
																				networkInterface,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				300,
																				javax.swing.GroupLayout.PREFERRED_SIZE)
																		.addGap(10,
																				10,
																				10)
																		.addComponent(
																				startButton,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				100,
																				javax.swing.GroupLayout.PREFERRED_SIZE)))/*
																		.addComponent(
																				statsButton,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				100,
																				javax.swing.GroupLayout.PREFERRED_SIZE))*/
										.addGap(25, 25, 25)));
		jPanel1Layout
				.setVerticalGroup(jPanel1Layout
						.createParallelGroup(
								javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(
								jPanel1Layout
										.createSequentialGroup()
										.addGap(32, 32, 32)
										.addGroup(
												jPanel1Layout
														.createParallelGroup(
																javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(
																jLabel1,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																49,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(
																networkInterface,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																49,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(
																startButton,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																49,
																javax.swing.GroupLayout.PREFERRED_SIZE)/*
														.addComponent(
																statsButton,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																49,
																javax.swing.GroupLayout.PREFERRED_SIZE)*/)
										.addPreferredGap(
												javax.swing.LayoutStyle.ComponentPlacement.UNRELATED,
												11, Short.MAX_VALUE)
										.addComponent(
												jScrollPane1,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												189,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(18, 18, 18)
										.addComponent(
												jScrollPane2,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												227,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(18, 18, 18)
										.addComponent(
												totalPanel,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)
										.addContainerGap()));

		javax.swing.GroupLayout layout = new javax.swing.GroupLayout(
				getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(
				javax.swing.GroupLayout.Alignment.LEADING).addComponent(
				jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE,
				javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));
		layout.setVerticalGroup(layout.createParallelGroup(
				javax.swing.GroupLayout.Alignment.LEADING).addComponent(
				jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE,
				javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));

		setExtendedState(JFrame.MAXIMIZED_BOTH);
		pack();
	}// </editor-fold>//GEN-END:initComponents

	private void networkInterfaceActionPerformed(java.awt.event.ActionEvent evt) {
		// TODO add your handling code here:
	}

	private void startButtonActionPerformed(java.awt.event.ActionEvent evt) {
		// TODO add your handling code here:
		this.ipv6SnifferControl.startOrStopCapture();
	}
	
	private void statsButtonActionPerformed(java.awt.event.ActionEvent evt) {
		// TODO add your handling code here:
		String stats = this.ipv6SnifferControl.getStatsCapture();
		JOptionPane.showMessageDialog(null, stats);
	}

	private void tableSelectActionPerformed(ListSelectionEvent e) {
		// TODO add your handling code here:
		if (!e.getValueIsAdjusting()) {
			Object selected = this.packetTable.getModel().getValueAt(
					this.packetTable.getSelectedRow(), 0);
			System.out.println("The selected values are: " + selected);
			this.ipv6SnifferControl.updateDetailPacketTree(Integer
					.valueOf(selected + ""));
			for (int i = 0; i < detailPacketTree.getRowCount(); i++) {
				detailPacketTree.expandRow(i);
			}
		}
	}

	/**
	 * @param args
	 *            the command line arguments
	 */
	public static void main(String args[]) {
		System.out.println(System.getProperty("java.library.path"));
		/* Create and display the form */
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				new SnifferFrame().setVisible(true);
				frame.setExtendedState(JFrame.MAXIMIZED_BOTH);
			}
		});
		/*javax.swing.SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                createAndShowGUI();
            }
        });*/
	}
	
	private static void createAndShowGUI() {
		

	}

	// Variables declaration - do not modify//GEN-BEGIN:variables
	private javax.swing.JTree detailPacketTree;
	//private javax.swing.JRadioButton ipv6OnlyButton;
	private javax.swing.JLabel jLabel1;
	private javax.swing.JPanel jPanel1;
	private javax.swing.JScrollPane jScrollPane1;
	private javax.swing.JScrollPane jScrollPane2;
	private javax.swing.JComboBox<String> networkInterface;
	private javax.swing.JTable packetTable;
	private javax.swing.JButton startButton;
	private javax.swing.JButton statsButton;
	private javax.swing.JScrollPane totalPanel;
	private javax.swing.JTextArea textArea;
	// End of variables declaration//GEN-END:variables
}
