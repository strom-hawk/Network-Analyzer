package networkanalyzer;

import jpcap.*;

class DetectDevices
{
    private static NetworkInterface[] devices;
    
    public void getDeviceList()
    {
        devices = JpcapCaptor.getDeviceList();
        System.out.println("available devices");
        for(int i=0; i<devices.length; i++)
        {
            System.out.println(devices[i].description);
        } 
    }
    public static void main(String[] args)
    {
       DetectDevices obj = new DetectDevices();
       obj.getDeviceList();
    }
}
