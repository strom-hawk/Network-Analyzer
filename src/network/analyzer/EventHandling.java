package network.analyzer;

import java.awt.event.*;
import java.awt.*;
import java.io.*;
import javax.swing.*;
import networkanalyzer.OpenDevice;

public class EventHandling extends MouseAdapter implements ActionListener
{
    NetworkAnalyzer obj = new NetworkAnalyzer(false);              //1.CREATE OBJECT OF NETWORK ANALYZER CLASS
    OpenDevice openObj = new OpenDevice();
    PacketAnalysis packetObj = new PacketAnalysis();
    
    public EventHandling(NetworkAnalyzer obj)                       //2.CONSTRUCTOR WITH PARAMETER AS OBJECT OF MAIN CLASS
    {
        this.obj = obj;                                             //3.REFERENCE OF OBJECT
    }
    
    public void mouseClicked(MouseEvent e)                          //4.OVERRIDES MOUSE CLICKED EVENT METHOD
    {
        if (e.getClickCount() == 1)
        {
            obj.index = obj.deviceSelectionList.getSelectedIndex();
            //TRANSFERING CONTROL TO NETWORK ANALYZER
            obj.captureInterface(obj.index);
        }
        
        if (e.getClickCount() == 2)
        {
            obj.index = obj.deviceSelectionList.getSelectedIndex();
            //TRANSFERING CONTROL TO NETWORK ANALYZER
            obj.capturePackets(obj.index);
        }
    }
    
    
    public void actionPerformed(ActionEvent ae)
    {
        String msg = null;
        msg = ae.getActionCommand();
        
        if(msg.equals("close panel 4"))
        {
            System.out.println("close button clicked");
            obj.mainFrame.remove(obj.panel4);
            obj.mainFrame.add(obj.panel2);
            obj.packetGraph.setEnabled(true);
            obj.mainFrame.repaint();
        }
        
        
        if(msg.equals("Exit"))
        {
            System.out.println(msg);
            System.exit(0);
        }
                       
        if (msg.equals("save") || msg.equals("Save"))
        {
            JFileChooser saveDialogBox = new JFileChooser();
            saveDialogBox.setDialogTitle("Save File");
            int option = saveDialogBox.showSaveDialog(obj.mainFrame);
            if(option == 0)     // IN PLACE OF 0 THIS CAN WORK JFileChooser.APPROVE_OPTION)
            {
                try(FileWriter fw = new FileWriter(saveDialogBox.getSelectedFile())) 
                {
                    try
                    {
                        fw.write(obj.saveToFile);
                    }
                    catch(Exception E)
                    {
                        JOptionPane.showMessageDialog(null, "Cannot Write To File.");
                    }
                }
                catch(Exception E)
                {
                    JOptionPane.showMessageDialog(null, "Cannot Open Save Dialog Box.");
                }
            }
        }
        
        if (msg.equals("start") || msg.equals("Start Capturing"))
        {   
            try
            {
                obj.index = obj.deviceSelectionList.getSelectedIndex();
                if(obj.index != -1)
                {
                    //TRANSFERING CONTROL TO NETWORK ANALYZER
                    obj.capturePackets(obj.index);
                }
                else
                {
                    //SHOWS UP MESSAGE IN A DIALOG BOX
                    JOptionPane.showMessageDialog(null, "Interface Not Selected.");
                    
                }
            }
            catch(Exception E)
            {
                //SHOWS UP MESSAGE IN A DIALOG BOX
                JOptionPane.showMessageDialog(null, "Interface Not Selected.");
            }
        }
        
        if (msg.equals("stop") || msg.equals("Stop Capturing"))
        {
            try
            {
                obj.interrupt();
            }
            catch(Exception E)
            {
                JOptionPane.showMessageDialog(null,"Capturing Not Started Yet");
            }
        }
        
        
        if (msg.equals("Refresh Interfaces"))
        {
            
            JOptionPane.showMessageDialog(null, "All Interfaces Refreshed.");
        }
        
        //----------------------------->
        //CREATE GRAPH FOR DIFFERENT PACKETS CAPTURED
        if(msg.equals("Create Packet Graph"))
        {
            try
            {
                obj.packetGraph.setEnabled(false);
                packetObj.openFile();
                int temp = packetObj.returnValue;   //TEMP IS REQUIRED BECAUSE IT TRANSFERS THE CONTROL  
                if ( temp == 0)                     //THROUGH MAIN THREAD.
                {
                    obj.tcp = packetObj.tcp;
                    obj.udp = packetObj.udp;
                    obj.arp = packetObj.arp;
                    obj.other = packetObj.other;
                    obj.barGraph();
                }
            }
            catch(Exception E)
            {
                
            }
        }
        
        //----------------------------->
        //ABOUT US SECTION
        if (msg.equals("About Us"))
        {
            final int widthAbout = 300;
            final int heightAbout = 400;
            JFrame about = new JFrame("About:");
            about.setSize(widthAbout,heightAbout);
            about.setResizable(false);
            about.setLocation(500,100);
            
            about.setLayout(null);
            
            JLabel l = new JLabel();
            l.setIcon(new ImageIcon("/home/saurav/NetBeansProjects/Network Analyzer/Icon/about.png"));
            l.setBounds(0,10,300,200);
            
            String text = "Product Version: 1.1\nRequired JDK Version: 1.7 32-bit\nCompany: X-Speed Corporation\n\n"
                    + "Copyright © 2017–2020\nThe Files Authors";
            
            JTextArea j = new JTextArea(text, 0,150);
            j.setFont(new Font("Tahoma", Font.BOLD, 13));
            j.setBackground(new Color(229, 229, 229));
            j.setBounds(10,(heightAbout/2) + 50,widthAbout-20,130);
            
            
            about.add(l);
            about.add(j);
            about.setVisible(true);
            about.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        }
        
        
        //----------------------------->
        //HOME EVENT HANDLING SECTION
        if(msg.equals("home") || (msg.equals("Home")) ||msg.equals("Restart Application"))
        {
            int value = JOptionPane.showConfirmDialog(null,"Reset All Values?","Confirm Dialog Box",JOptionPane.YES_NO_OPTION);
            if(value == JOptionPane.YES_OPTION)
            {
                obj.mainFrame.setVisible(false);
                new NetworkAnalyzer(true);
            }
            
        }
        
        //----------------------------->
        //FILTERING OF PACKETS STARTED
        if(msg.equals("filterPackets"))
        {
            //GETS THE VALUE FROM FILTER TEXTFIELD
            String value = obj.filter.getText();
            
            //----------------------------->
            //IP PACKETS
            if(value.equals("ip") || value.equals("IP"))
            {
                try
                {
                    openObj.selectedDevice.setFilter("ip", true);
                    obj.filter.setBackground(new Color(46, 204, 113));
                    System.out.println(value);
                }
                catch(IOException e)
                {
                    e.printStackTrace();
                }
            }
            //----------------------------->
            //ARP PACKETS
            else if(value.equals("arp") || value.equals("ARP"))
            {
                try
                {
                    openObj.selectedDevice.setFilter("arp", true);
                    obj.filter.setBackground(new Color(46, 204, 113));
                    System.out.println(value);
                }
                catch(IOException e)
                {
                    e.printStackTrace();
                }
            }
            //----------------------------->
            //UDP PACKETS
            else if(value.equals("udp") || value.equals("UDP"))
            {
                try
                {
                    openObj.selectedDevice.setFilter("udp", true);
                    obj.filter.setBackground(new Color(46, 204, 113));
                    System.out.println(value);
                }
                catch(IOException e)
                {
                    e.printStackTrace();
                }
            }            
            //----------------------------->
            //TCP PACKETS
            else if(value.equals("tcp") || value.equals("TCP"))
            {
                try
                {
                    openObj.selectedDevice.setFilter("ip and tcp", true);
                    obj.filter.setBackground(new Color(46, 204, 113));
                    System.out.println(value);
                }
                catch(IOException e)
                {
                    e.printStackTrace();
                }
            }
            //----------------------------->
            //NO FILTER
            else if(value.equals(""))
            {
                obj.filter.setBackground(Color.white);
                try
                {
                    openObj.selectedDevice.setFilter("",true);
                    obj.filter.setBackground(Color.white);
                    System.out.println(value);
                }
                catch(IOException e)
                {
                    e.printStackTrace();
                }
            }
            //----------------------------->
            //WRONG ENTRY
            else
            {
                obj.filter.setBackground(new Color(247, 131, 121));
                System.out.println(value);
            }
            //----------------------------->
        }
        //FILTERING OF PACKETS OVER
        //-----------------------------> 
    }
}
