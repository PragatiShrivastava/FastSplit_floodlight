package net.floodlightcontroller.mobilityprotocols;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.topology.NodePortTuple;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MobilityProtocols implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected IDeviceService deviceservice;
	protected ILinkDiscoveryService linkservices;
	protected IOFSwitchService switchService;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	private devicelistener dlisten;
	// Stores the device mac attached to which switch-port
	protected Map<Long ,OFPort> mactoSwitchport;
	protected static Map<DatapathId, Integer> switchmap;
	public static int nodevices=0;
	public static int nos=0;
    public static int [][]shortestpath =null;
    public static int [][] adj=null;
 // to record all flow
    public FileWriter fileflow;
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		 return MobilityProtocols.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
		        new ArrayList<Class<? extends IFloodlightService>>();
		    l.add(IFloodlightProviderService.class);
		    l.add(IDeviceService.class);
		    l.add(ILinkDiscoveryService.class);
		    l.add(IOFSwitchService.class);
		    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		 floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		 deviceservice = context.getServiceImpl(IDeviceService.class);
		 linkservices = context.getServiceImpl(ILinkDiscoveryService.class);
		 switchService = context.getServiceImpl(IOFSwitchService.class);
		    macAddresses = new ConcurrentSkipListSet<Long>();
		    logger = LoggerFactory.getLogger(MobilityProtocols.class);
		    switchmap = new HashMap<DatapathId, Integer>();
		    dlisten = new devicelistener();
		    try {
				fileflow = new FileWriter("/Users/pragati/Desktop/flow/new/flowrules.txt", true); 
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		 floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		 deviceservice.addListener(this.dlisten);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		switch (msg.getType()) {
		case PACKET_IN:
		Ethernet eth =
                IFloodlightProviderService.bcStore.get(cntx,
                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
 
        Long sourceMACHash = eth.getSourceMACAddress().getLong();
        if (!macAddresses.contains(sourceMACHash)) {
            macAddresses.add(sourceMACHash);
            logger.info("MAC Address: {} seen on switch: {}",
                    eth.getSourceMACAddress().toString(),
                    sw.getId().toString());
        }
        
//        OFPacketIn pi = (OFPacketIn) msg; 
//        if(switchService.getAllSwitchDpids().size()>2)
//        	   findroute(finddpid(1),pi.getInPort(), finddpid(2),pi.getInPort());
//        	
		default:
			break;
		}
		
        return Command.CONTINUE;
	}
	
	//create a map to manage DPID to integer indexing
	protected void SetSwitchMap()
	{
		Set<DatapathId> switches = switchService.getAllSwitchDpids();
		int i=1;
		for (DatapathId temp: switches)
		{
			switchmap.put(temp, i);
			i++;
			 System.out.println("switchmap:"+ temp+"="+switchmap.get(temp));
		}
		
	}
	///////////////////////
	// find adj matrix
	 public int[][] findadj()
	 {
		 Map<Link,LinkInfo> links = linkservices.getLinks();
			DatapathId s;
			DatapathId d;

		// define adjacency matrix. (by default initialize to zero)(1 to nos)
					 adj= new int[nos+1][nos+1];
					
					for (Link link : links.keySet()) {
						   s= link.getSrc();
					       d= link.getDst();
					       int si, di;
					       si= switchmap.get(s);
					       di= switchmap.get(d);
					       adj[si][di]=1;
					       System.out.println("adj ="+si+","+di);

					}
					
					for(int i=0, j=0; j <= nos; j++  )
					{
						adj[i][j]=99999;
						adj[j][i]=99999;
						
					}
					
					for(int i=1; i< nos+1; i++)
					{
						for(int j=1; j< nos+1; j++)
						{
							//System.out.print("adj value= "+i+","+j+ adj[i][j]);
							if(adj[i][j] == 0 && i!=j)
								adj[i][j]=99999;
						}
			            //System.out.println("\n");
					}
					adj[0][0]=99999;  // for n*n matrix is [1-n][1-n]  i.e. matrix[n+1][n+1]
					for(int i=0; i< adj.length; i++)
					{
						for(int j=0; j<adj.length; j++)
							System.out.print(adj[i][j]+"   ");
					  System.out.println();
					}
					return adj;
	 }
	/// find shortest path using DFS
	   public int [] findPath(DatapathId s, DatapathId d)
	   {
		   int src, desti;
		   src= switchmap.get(s);
		   desti=switchmap.get(d);
		   //int [][] adj = findadj();
		   int [][] adjmat = new int[adj.length][adj.length];
		//      System.out.println("adjmatrixxxx");
			for(int i=0; i< adj.length; i++)
			{
				for(int j=0; j< adj.length; j++)
				{
					if(adj[i][j] == 99999)
						adjmat[i][j]= 0;
					else
						adjmat[i][j]= adj[i][j];

					//System.out.print(adjmat[i][j] + "\t");
				}
				//System.out.println();
			}
					
		   
			 DFS dfs = new DFS();
			 int splength = shortestpath[src][desti];
			
			 int[] path= new int[splength+1];
			 //System.out.print("source="+src+", desti="+desti+ "SPL::"+splength);
	       dfs.dfs(adjmat, src, desti, splength, nos, path);
	       
	       //System.out.println("shortest path b/w" + src + desti);    
	       try {
	    	   createfile("shortest path b/w" + src + desti, fileflow);
				createfile("dfs path of length ::"+ splength +"\n",fileflow);
				
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
	      // System.out.println("shortest path length++++++++"+"\t path.length="+path.length);
	       for(int i=0; i< path.length; i++)   
	       {
	 /////////// file///////
	           try {
					createfile("->"+ path[i] +"\n", fileflow);
					System.out.println("->" + path[i]);    
				       
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
	       }
	           
	       return path ;
	   }
	 
//////////find route  
public Route findroute(DatapathId sw1, OFPort port1, DatapathId sw2, OFPort port2)
 {	System.out.println("my routeeeeeeeeeeeeeeeeeeee:283");
	RouteId rid = new RouteId(sw1,sw2);
	   if(islink(sw1, sw2))
		   return new Route(rid, linktupple(sw1, sw2));
	   if(sw1.equals(sw2))
		   return null;
	   System.out.println("my routeeeeeeeeeeeeeeeeeeee:289");
	   int path[] =findPath(sw1,sw2);
	   System.out.println("my routeeeeeeeeeeeeeeeeeeee:291");
	   List<NodePortTuple> p = convertTopath(sw1, port1, sw2, port2, path );
	   System.out.println("my routeeeeeeeeeeeeeeeeeeee:293");
	   Route route = new Route(rid,p);
	      /////////// file///////
	                try {
						createfile("call to find path b/w"+ sw1+ "\t" + port1+ "\t" + sw2+ "\t" + port2 + "\n", fileflow);
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

	   return route;
 }
private boolean islink(DatapathId src, DatapathId desti) {
	// TODO Auto-generated method stub
	   Map<Link,LinkInfo> links = linkservices.getLinks();
		DatapathId s;
		DatapathId d;
				
				for (Link ilink : links.keySet()) {
//					System.out.println("SrcSwitch="+ilink.getSrc()+", SrcPort="+ilink.getSrcPort()
//							+", DstSwitch="+ilink.getDst()+", DstPort="+ilink.getDstPort());
					   s= ilink.getSrc();
				       d= ilink.getDst();
				       if(s.equals(src) && d.equals(desti))
				    	   return true;
				}
				    
	return false;
}
private List<NodePortTuple> linktupple(DatapathId src , DatapathId desti) {
	// TODO Auto-generated method stub
	   Map<Link,LinkInfo> links = linkservices.getLinks();
		DatapathId s;
		DatapathId d;
		List<NodePortTuple> ll = new ArrayList<NodePortTuple>();
				for (Link ilink : links.keySet()) {
					   s= ilink.getSrc();
				       d= ilink.getDst();
				       if(s.equals(src) && d.equals(desti))
				       {
				    	   ll.add(new NodePortTuple(s,ilink.getSrcPort()));
				    	   ll.add(new NodePortTuple(d,ilink.getDstPort()));
				    	   return ll;
				       }
				}
	return null;
}
private Link getlink(DatapathId src, DatapathId desti)
{
	Map<DatapathId, Set<Link>> linkmap = linkservices.getSwitchLinks();
	Set<Link> srclink = linkmap.get(src);
	for(Link l: srclink)
	{
		if(l.getDst().equals(desti))
			return l;
	}
	return null;
}
// find reverse match int to DPID
private DatapathId finddpid(int i)
{
	for(Map.Entry<DatapathId, Integer> entry: switchmap.entrySet())
	{
		if(entry.getValue().equals(i))
			return entry.getKey();
	}
	return null;
}

private List<NodePortTuple> convertTopath(DatapathId src,OFPort sp, DatapathId dest,OFPort dp, int[] path) {
	// TODO Auto-generated method stub
	   List<NodePortTuple> route = new ArrayList<NodePortTuple>();
	   route.add(new NodePortTuple(src,sp));
	   for(int i =0; i<path.length-1; i++ )
	   {
		   DatapathId si, di;
		   si= finddpid(path[i]);
		   di= finddpid(path[i+1]);
		   if(si!=null && di!=null)
		   {
			   Link l = getlink(si,di);
			   NodePortTuple s, d;
			   s = new NodePortTuple(l.getSrc(),l.getSrcPort());
			   d = new NodePortTuple(l.getDst(), l.getDstPort());
			   route.add(s);
			   route.add(d);
		   }
	     else
		   System.out.println("key does not matchessssssss");
		   
		   
	   }
	   route.add(new NodePortTuple(dest,dp));
/////////// file///////
       try {
    	   createfile("**************************************\n", fileflow);
			createfile("convertest path in to sw-port:"+ route +"\n", fileflow);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} 
	return route;
}

	//
	//IDevicelistener**********************
    private class devicelistener implements IDeviceListener
    {

		@Override
		public String getName() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public boolean isCallbackOrderingPrereq(String type, String name) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean isCallbackOrderingPostreq(String type, String name) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void deviceAdded(IDevice device) {
			// TODO Auto-generated method stub
			nodevices++;
			System.out.println("Device added!!!!!");
			if(nodevices == 4) //all topology is established
			{
				SetSwitchMap();
			    findadj();
			    Floyd f = new Floyd();
				shortestpath =	f.floydWarshall(adj, nos);
			}
			
			// initialize number of switches in topology
			if(nos < switchService.getAllSwitchDpids().size())
				 nos= switchService.getAllSwitchDpids().size();
		}

		@Override
		public void deviceRemoved(IDevice device) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void deviceMoved(IDevice device) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void deviceIPV4AddrChanged(IDevice device) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void deviceVlanChanged(IDevice device) {
			// TODO Auto-generated method stub
			
		}
    	
    }

    /// store some outputs in file for debugging
    public void createfile(String x, FileWriter f) throws IOException
	{
    	 BufferedWriter bw = new BufferedWriter(f);
				bw.write(x + "\n"); 
				bw.flush();
				//bw.close();

	}

	
}
