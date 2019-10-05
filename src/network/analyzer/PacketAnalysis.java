package network.analyzer;

import java.awt.*;
import javax.swing.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class PacketAnalysis
{
    NetworkAnalyzer obj = new NetworkAnalyzer(false);
    public JFileChooser openDialog;
    public JFrame window;
    public int returnValue;
    
    int tcp;
    int udp;
    int arp;
    int other;
          
    //----------------------------->
    //OPENS A SAVED FILE AND COUNT DIFFERENT PACKETS
    public void openFile() throws FileNotFoundException
    {
        tcp = udp = arp = other = 0;
        openDialog = new JFileChooser();
        openDialog.setDialogTitle("Choose A Packet File");
        returnValue = openDialog.showOpenDialog(obj.mainFrame);
        if(returnValue == 0)
        {
            File file = openDialog.getSelectedFile();
            String line = null;
            Scanner scanFile = new Scanner(file);
            String[] token = null;
            while(scanFile.hasNext())
            {
                line = scanFile.nextLine();
                if(line.contains("TCP"))
                {
                        ++tcp;
                }
                else if(line.contains("UDP"))
                {
                    ++udp;
                }
                else if(line.contains("ARP"))
                {
                    ++arp;
                }
                else
                {
                    ++other;
                }
            }
            System.out.println("Total Packets:");
            System.out.println("tcp :" + tcp);
            System.out.println("udp :" + udp);
            System.out.println("arp :" + arp);
            System.out.println("other " + other);
        }
    }
}