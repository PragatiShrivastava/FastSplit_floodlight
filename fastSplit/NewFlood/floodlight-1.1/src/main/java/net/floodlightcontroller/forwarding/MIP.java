/**
 *    Copyright 2011, Big Switch Networks, Inc.
 *    Originally created by David Erickson, Stanford University
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package net.floodlightcontroller.forwarding;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.core.annotations.LogMessageCategory;
import net.floodlightcontroller.core.annotations.LogMessageDoc;
import net.floodlightcontroller.core.annotations.LogMessageDocs;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.debugcounter.IDebugCounterService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.mobilityprotocols.DFS;
import net.floodlightcontroller.mobilityprotocols.Floyd;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.MatchUtils;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@LogMessageCategory("Flow Programming")
public class MIP extends ForwardingBase implements IFloodlightModule {
	protected static Logger log = LoggerFactory.getLogger(MIP.class);
	public FileWriter filepktin;
	public FileWriter fileflow;
	private devicelistener dlisten;
	// store the attachment points for hosts
		private Map<Long, ArrayList<SwitchPort>> mactoattachment;
   //switch port status
		private static PortChangeType switchportstatus = PortChangeType.DOWN;
		// listener to switch behaviour
		private switchlistener slisten;
		// no of switch added
		public static int nos=0;
		 // store device pair comunicating to each other
		public Map<Long, Long> communicatingpair;
		// store match to delete
		protected static Map<DatapathId, Integer> switchmap;
		// no of device added
		public static int nodevices=0;
		// adjecency
		public static int [][]shortestpath =null;
	    public static int [][] adj=null;
	 // store switch to match mapping for deleting specific flow when needed
		private SwitchtoMatch switchtomatch;
		// setting flow priority incremental
		public static int flow_priority=1;
		// moving device object
		 public static IDevice movingdevice = null;
		 /// **** Evalaution perameters*****
		 public static int noFlows =0;
		 public static int noSwitchtoconfig = 0;
		 public static int noSwitchmatches  =0;   // similarity no. of switch matches to previous
	
	@Override
	@LogMessageDoc(level="ERROR",
	message="Unexpected decision made for this packet-in={}",
	explanation="An unsupported PacketIn decision has been " +
			"passed to the flow programming component",
			recommendation=LogMessageDoc.REPORT_CONTROLLER_BUG)
	public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		// We found a routing decision (i.e. Firewall is enabled... it's the only thing that makes RoutingDecisions)
		if (decision != null) {
			if (log.isTraceEnabled()) {
				log.trace("Forwaring decision={} was made for PacketIn={}", decision.getRoutingAction().toString(), pi);
			}

			switch(decision.getRoutingAction()) {
			case NONE:
				// don't do anything
				return Command.CONTINUE;
			case FORWARD_OR_FLOOD:
			case FORWARD:
				doForwardFlow(sw, pi, cntx, false);
				return Command.CONTINUE;
			case MULTICAST:
				// treat as broadcast
				doFlood(sw, pi, cntx);
				return Command.CONTINUE;
			case DROP:
				doDropFlow(sw, pi, decision, cntx);
				return Command.CONTINUE;
			default:
				log.error("Unexpected decision made for this packet-in={}", pi, decision.getRoutingAction());
				return Command.CONTINUE;
			}
		} else { // No routing decision was found. Forward to destination or flood if bcast or mcast.
			if (log.isTraceEnabled()) {
				log.trace("No decision was made for PacketIn={}, forwarding", pi);
			}

			if (eth.isBroadcast() || eth.isMulticast()) {
				doFlood(sw, pi, cntx);
			} else {
				doForwardFlow(sw, pi, cntx, false);
			}
		}

		return Command.CONTINUE;
	}

	@LogMessageDoc(level="ERROR",
			message="Failure writing drop flow mod",
			explanation="An I/O error occured while trying to write a " +
					"drop flow mod to a switch",
					recommendation=LogMessageDoc.CHECK_SWITCH)
	protected void doDropFlow(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		Match m = createMatchFromPacket(sw, inPort, cntx);
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd(); // this will be a drop-flow; a flow that will not output to any ports
		List<OFAction> actions = new ArrayList<OFAction>(); // set no action to drop
		U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);

		fmb.setCookie(cookie)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(m)
		.setActions(actions) // empty list
		.setPriority(FLOWMOD_DEFAULT_PRIORITY);

		try {
			if (log.isDebugEnabled()) {
				log.debug("write drop flow-mod sw={} match={} flow-mod={}",
						new Object[] { sw, m, fmb.build() });
			}
			boolean dampened = messageDamper.write(sw, fmb.build());
			log.debug("OFMessage dampened: {}", dampened);
		} catch (IOException e) {
			log.error("Failure writing drop flow mod", e);
		}
	}

	protected void doForwardFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, boolean requestFlowRemovedNotifn) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		// Check if we have the location of the destination
		IDevice dstDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_DST_DEVICE);

		if (dstDevice != null) {
			IDevice srcDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE);
			DatapathId srcIsland = topologyService.getL2DomainId(sw.getId());

			if (srcDevice == null) {
				log.debug("No device entry found for source device");
				return;
			}
			if (srcIsland == null) {
				log.debug("No openflow island found for source {}/{}",
						sw.getId().toString(), inPort);
				return;
			}

			try {
				createfile("PKT_IN by switch:"+sw.getId()+"\n", filepktin);
				createfile("PKT_IN "+"host:"+ srcDevice.getMACAddressString()+"\n", filepktin);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			  ////********** Store info about communicating host **********////// (destination to source)
			communicatingpair.put(dstDevice.getDeviceKey(), srcDevice.getDeviceKey());
			// switch status up and H1 send a pkt_in by ping
			if(movingdevice != null && switchportstatus.equals(PortChangeType.UP) && movingdevice.getDeviceKey().equals(srcDevice.getDeviceKey()))
			{
				//deploy flow from CN to MN new location of high priority
				System.out.println("tempflow called moving device:"+ movingdevice.getIPv4Addresses());
				tempdeployflow(movingdevice);
				return;
			}
			// Validate that we have a destination known on the same island
			// Validate that the source and destination are not on the same switchport
			boolean on_same_island = false;
			boolean on_same_if = false;
			for (SwitchPort dstDap : dstDevice.getAttachmentPoints()) {
				DatapathId dstSwDpid = dstDap.getSwitchDPID();
				DatapathId dstIsland = topologyService.getL2DomainId(dstSwDpid);
				if ((dstIsland != null) && dstIsland.equals(srcIsland)) {
					on_same_island = true;
					if (sw.getId().equals(dstSwDpid) && inPort.equals(dstDap.getPort())) {
						on_same_if = true;
					}
					break;
				}
			}

			if (!on_same_island) {
				// Flood since we don't know the dst device
				if (log.isTraceEnabled()) {
					log.trace("No first hop island found for destination " +
							"device {}, Action = flooding", dstDevice);
				}
				doFlood(sw, pi, cntx);
				return;
			}

			if (on_same_if) {
				if (log.isTraceEnabled()) {
					log.trace("Both source and destination are on the same " +
							"switch/port {}/{}, Action = NOP",
							sw.toString(), inPort);
				}
				return;
			}

			// Install all the routes where both src and dst have attachment
			// points.  Since the lists are stored in sorted order we can
			// traverse the attachment points in O(m+n) time
			SwitchPort[] srcDaps = srcDevice.getAttachmentPoints();
			Arrays.sort(srcDaps, clusterIdComparator);
			SwitchPort[] dstDaps = dstDevice.getAttachmentPoints();
			Arrays.sort(dstDaps, clusterIdComparator);

			int iSrcDaps = 0, iDstDaps = 0;

			while ((iSrcDaps < srcDaps.length) && (iDstDaps < dstDaps.length)) {
				SwitchPort srcDap = srcDaps[iSrcDaps];
				SwitchPort dstDap = dstDaps[iDstDaps];

				// srcCluster and dstCluster here cannot be null as
				// every switch will be at least in its own L2 domain.
				DatapathId srcCluster = topologyService.getL2DomainId(srcDap.getSwitchDPID());
				DatapathId dstCluster = topologyService.getL2DomainId(dstDap.getSwitchDPID());

				int srcVsDest = srcCluster.compareTo(dstCluster);
				if (srcVsDest == 0) {
					if (!srcDap.equals(dstDap)) {
						Route route =
								routingEngineService.getRoute(srcDap.getSwitchDPID(), 
										srcDap.getPort(),
										dstDap.getSwitchDPID(),
										dstDap.getPort(), U64.of(0)); //cookie = 0, i.e., default route
						if (route != null) {
							if (log.isTraceEnabled()) {
								log.trace("pushRoute inPort={} route={} " +
										"destination={}:{}",
										new Object[] { inPort, route,
										dstDap.getSwitchDPID(),
										dstDap.getPort()});
							}

							U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);

							Match m = createMatchFromPacket(sw, inPort, cntx);
                            
							 //store match for deleting further
							this.switchtomatch.AddMatch(sw, m);
							
							pushRoute(route, m, pi, sw.getId(), cookie,
									cntx, requestFlowRemovedNotifn, false,
									OFFlowModCommand.ADD);
						}
					}
					iSrcDaps++;
					iDstDaps++;
				} else if (srcVsDest < 0) {
					iSrcDaps++;
				} else {
					iDstDaps++;
				}
			}
		} else {
			// Flood since we don't know the dst device
			doFlood(sw, pi, cntx);
		}
	}

	/**
	 * Instead of using the Firewall's routing decision Match, which might be as general
	 * as "in_port" and inadvertently Match packets erroneously, construct a more
	 * specific Match based on the deserialized OFPacketIn's payload, which has been 
	 * placed in the FloodlightContext already by the Controller.
	 * 
	 * @param sw, the switch on which the packet was received
	 * @param inPort, the ingress switch port on which the packet was received
	 * @param cntx, the current context which contains the deserialized packet
	 * @return a composed Match object based on the provided information
	 */
	protected Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {
		// The packet in match will only contain the port number.
		// We need to add in specifics for the hosts we're routing between.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
		MacAddress srcMac = eth.getSourceMACAddress();
		MacAddress dstMac = eth.getDestinationMACAddress();

		// A retentive builder will remember all MatchFields of the parent the builder was generated from
		// With a normal builder, all parent MatchFields will be lost if any MatchFields are added, mod, del
		// TODO (This is a bug in Loxigen and the retentive builder is a workaround.)
		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.IN_PORT, inPort)
		.setExact(MatchField.ETH_SRC, srcMac)
		.setExact(MatchField.ETH_DST, dstMac);

		if (!vlan.equals(VlanVid.ZERO)) {
			mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
		}

		// TODO Detect switch type and match to create hardware-implemented flow
		// TODO Set option in config file to support specific or MAC-only matches
		if (eth.getEtherType() == EthType.IPv4) { /* shallow check for equality is okay for EthType */
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4Address srcIp = ip.getSourceAddress();
			IPv4Address dstIp = ip.getDestinationAddress();
			mb.setExact(MatchField.IPV4_SRC, srcIp)
			.setExact(MatchField.IPV4_DST, dstIp)
			.setExact(MatchField.ETH_TYPE, EthType.IPv4);

			if (ip.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ip.getPayload();
				mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
				.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
				.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
			} else if (ip.getProtocol().equals(IpProtocol.UDP)) {
				UDP udp = (UDP) ip.getPayload();
				mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
				.setExact(MatchField.UDP_SRC, udp.getSourcePort())
				.setExact(MatchField.UDP_DST, udp.getDestinationPort());
			}	
		} else if (eth.getEtherType() == EthType.ARP) { /* shallow check for equality is okay for EthType */
			mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
		}
		return mb.build();
	}
	
	/**
	 * Creates a OFPacketOut with the OFPacketIn data that is flooded on all ports unless
	 * the port is blocked, in which case the packet will be dropped.
	 * @param sw The switch that receives the OFPacketIn
	 * @param pi The OFPacketIn that came to the switch
	 * @param cntx The FloodlightContext associated with this OFPacketIn
	 */
	@LogMessageDoc(level="ERROR",
			message="Failure writing PacketOut " +
					"switch={switch} packet-in={packet-in} " +
					"packet-out={packet-out}",
					explanation="An I/O error occured while writing a packet " +
							"out message to the switch",
							recommendation=LogMessageDoc.CHECK_SWITCH)
	protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		if (topologyService.isIncomingBroadcastAllowed(sw.getId(), inPort) == false) {
			if (log.isTraceEnabled()) {
				log.trace("doFlood, drop broadcast packet, pi={}, " +
						"from a blocked port, srcSwitch=[{},{}], linkInfo={}",
						new Object[] {pi, sw.getId(), inPort});
			}
			return;
		}

		// Set Action to flood
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		List<OFAction> actions = new ArrayList<OFAction>();
		if (sw.hasAttribute(IOFSwitch.PROP_SUPPORTS_OFPP_FLOOD)) {
			actions.add(sw.getOFFactory().actions().output(OFPort.FLOOD, Integer.MAX_VALUE)); // FLOOD is a more selective/efficient version of ALL
		} else {
			actions.add(sw.getOFFactory().actions().output(OFPort.ALL, Integer.MAX_VALUE));
		}
		pob.setActions(actions);

		// set buffer-id, in-port and packet-data based on packet-in
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		pob.setData(pi.getData());

		try {
			if (log.isTraceEnabled()) {
				log.trace("Writing flood PacketOut switch={} packet-in={} packet-out={}",
						new Object[] {sw, pi, pob.build()});
			}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			log.error("Failure writing PacketOut switch={} packet-in={} packet-out={}",
					new Object[] {sw, pi, pob.build()}, e);
		}

		return;
	}

	// IFloodlightModule methods

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// We don't export any services
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService>
	getServiceImpls() {
		// We don't have any services
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(IRoutingService.class);
		l.add(ITopologyService.class);
		l.add(IDebugCounterService.class);
		return l;
	}

	@Override
	@LogMessageDocs({
		@LogMessageDoc(level="WARN",
				message="Error parsing flow idle timeout, " +
						"using default of {number} seconds",
						explanation="The properties file contains an invalid " +
								"flow idle timeout",
								recommendation="Correct the idle timeout in the " +
				"properties file."),
				@LogMessageDoc(level="WARN",
				message="Error parsing flow hard timeout, " +
						"using default of {number} seconds",
						explanation="The properties file contains an invalid " +
								"flow hard timeout",
								recommendation="Correct the hard timeout in the " +
						"properties file.")
	})
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		super.init();
		this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		this.deviceManagerService = context.getServiceImpl(IDeviceService.class);
		this.routingEngineService = context.getServiceImpl(IRoutingService.class);
		this.topologyService = context.getServiceImpl(ITopologyService.class);
		this.debugCounterService = context.getServiceImpl(IDebugCounterService.class);
		this.switchService = context.getServiceImpl(IOFSwitchService.class);
		 this.dlisten = new devicelistener();
		 this.slisten = new switchlistener();
		 this.mactoattachment = new HashMap<Long, ArrayList<SwitchPort>>();
		 this.communicatingpair = new HashMap<Long, Long>();
		 this.switchmap = new HashMap<DatapathId, Integer>();
		 this.switchtomatch = new SwitchtoMatch(new HashMap<IOFSwitch,ArrayList<Match>>());
		 this.linkdiscoveryservices = context.getServiceImpl(ILinkDiscoveryService.class);
		 try {
				filepktin = new FileWriter("/Users/pragati/Desktop/flow/new/PKT-in.txt", true); 
				fileflow = new FileWriter("/Users/pragati/Desktop/flow/new/flowrules.txt", true); 
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
		Map<String, String> configParameters = context.getConfigParams(this);
		String tmp = configParameters.get("hard-timeout");
		if (tmp != null) {
			FLOWMOD_DEFAULT_HARD_TIMEOUT = Integer.parseInt(tmp);
			log.info("Default hard timeout set to {}.", FLOWMOD_DEFAULT_HARD_TIMEOUT);
		} else {
			log.info("Default hard timeout not configured. Using {}.", FLOWMOD_DEFAULT_HARD_TIMEOUT);
		}
		tmp = configParameters.get("idle-timeout");
		if (tmp != null) {
			FLOWMOD_DEFAULT_IDLE_TIMEOUT = Integer.parseInt(tmp);
			log.info("Default idle timeout set to {}.", FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		} else {
			log.info("Default idle timeout not configured. Using {}.", FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		}
		tmp = configParameters.get("priority");
		if (tmp != null) {
			FLOWMOD_DEFAULT_PRIORITY = Integer.parseInt(tmp);
			log.info("Default priority set to {}.", FLOWMOD_DEFAULT_PRIORITY);
		} else {
			log.info("Default priority not configured. Using {}.", FLOWMOD_DEFAULT_PRIORITY);
		}
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		super.startUp();
		deviceManagerService.addListener(this.dlisten);
		switchService.addOFSwitchListener(this.slisten);
	}
	 /// store some outputs in file for debugging
    public void createfile(String x, FileWriter f) throws IOException
	{
    	 BufferedWriter bw = new BufferedWriter(f);
				bw.write(x + "\n"); 
				bw.flush();
				//bw.close();

	}
    public void initiAttachment(IDevice device)
    {
    		 SwitchPort[] old = device.getAttachmentPoints();
    		 System.out.println("initiiiiiiiiiiiiiiiiiiiii");
    		 if(old.length > 0)
    		 {
    			 if(!mactoattachment.containsKey(device.getDeviceKey()))
    	         {
    				 mactoattachment.put(device.getDeviceKey(), new ArrayList<SwitchPort>()); 
    				 mactoattachment.get(device.getDeviceKey()).add(old[0]);
    	         }
    			 else
    			 {
    				 ArrayList<SwitchPort> temp = mactoattachment.get(device.getDeviceKey());
    				 int len = temp.size();
    				 // if the attachment point changed
    				 if(! temp.get(len-1).getSwitchDPID().equals(old[0].getSwitchDPID()) || ! temp.get(len-1).getPort().equals(old[0].getPort()))
    					 mactoattachment.get(device.getDeviceKey()).add(old[0]);
    				 
    			 }
        		 System.out.println("++++++++++no of attachmentpoint" + mactoattachment.get(device.getDeviceKey()).size() +".....value"  + old[0]);	 
        		 ArrayList<SwitchPort> s = mactoattachment.get(device.getDeviceKey());
        		 for(int i =0; i < mactoattachment.get(device.getDeviceKey()).size(); i++)
        		 {
        			 SwitchPort temp = s.get(i);
        			 System.out.println("device attachment point::" + temp.getSwitchDPID());
        		 }
        		 
    		 }
        		 
    }
    public IDevice findCN(IDevice device) {
		// TODO Auto-generated method stub
		IDevice CN = null;
		if(communicatingpair.containsKey(device.getDeviceKey()))
		{
			CN = deviceManagerService.getDevice(communicatingpair.get(device.getDeviceKey()));
		}
	
		return CN;
	}
  //create a map to manage DPID to integer indexing
  		protected void SetSwitchMap()
  		{
  			Set<DatapathId> switches = switchService.getAllSwitchDpids();
  			int i=1;
  			 System.out.println("setting switch map ................"+ "no of switches"+ switches.size());
  			for (DatapathId temp: switches)
  			{
  				switchmap.put(temp, i);
  				i++;
  				 System.out.println("switchmap:"+ temp+"="+switchmap.get(temp));
  			}
  			
  		}
  		
  	// find adj matrix
  			 public int[][] findadj()
  			 {
  				 Map<Link,LinkInfo> links = linkdiscoveryservices.getLinks();
  					DatapathId s;
  					DatapathId d;

  				// define adjacency matrix. (by default initialize to zero)(1 to nos)
  					System.out.println("nos--------"+nos);
  							 adj= new int[nos+2][nos+2];
  							
  							for (Link link : links.keySet()) {
  								   s= link.getSrc();
  							       d= link.getDst();
  							       int si, di;
  							       si= switchmap.get(s);
  							       di= switchmap.get(d);
  							       adj[si][di]=1;
  							       System.out.println("adj ="+si+","+di);

  							}
  							
  							for(int i=0, j=0; j <= nos+1; j++  )
  							{
  								adj[i][j]=99999;
  								adj[j][i]=99999;
  								
  							}
  							
  							for(int i=1; i<= nos+1; i++)
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
			System.out.println("device add::" + device.getIPv4Addresses());
			initiAttachment(device);
            nodevices++;
            if(nodevices == 2 && nos==9) //all topology is established call when all switches are added in to topology
			{
				System.out.println("nossssss="+ nos);
			    findadj();
			    Floyd f = new Floyd();
				shortestpath =	f.floydWarshall(adj, nos);
				//allswitchadded=true;
			}
			
		}

		@Override
		public void deviceRemoved(IDevice device) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void deviceMoved(IDevice device) {
			// TODO Auto-generated method stub
			System.out.println("device moved !!!!!!!!!!!!!!!!!!!!!!!!");
			System.out.println("switch STATUS:" + switchportstatus);
			// device is added to switchport and its up
			if(switchportstatus.equals(PortChangeType.UP))
			{
				initiAttachment(device);
				 movingdevice= device;
			}
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
    
    private class switchlistener implements IOFSwitchListener{

		@Override
		public void switchAdded(DatapathId switchId) {
			// TODO Auto-generated method stub
			nos++;
			System.out.println("switch added----------" + nos);
			if(nos == 9)
				SetSwitchMap();
			
		}

		@Override
		public void switchRemoved(DatapathId switchId) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void switchActivated(DatapathId switchId) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void switchPortChanged(DatapathId switchId, OFPortDesc port,
				PortChangeType type) {
			// TODO Auto-generated method stub
			System.out.println("*****************switchPortChanged type::"+ type );
			System.out.println(switchId + "//"+ port.getPortNo());
			switchportstatus= type;       
		}

		@Override
		public void switchChanged(DatapathId switchId) {
			// TODO Auto-generated method stub
			
		}
    	
    }
	private void deleteflow(IDevice device) {
		// TODO Auto-generated method stub
		Set<DatapathId> switches =switchService.getAllSwitchDpids();
		for(DatapathId swid : switches)
		{
			IOFSwitch sw = switchService.getActiveSwitch(swid);
			this.FlowDeletebywrite(device, sw);
		}
	}

	private void FlowDeletebywrite(IDevice device, IOFSwitch sw) {
		// TODO Auto-generated method stub
		 ArrayList<Match> m =	this.switchtomatch.GetMatch(sw);
		    if(m != null)
		    {
		    	  for(Match match : m)
		    	  {// if moving device is source or destination in specific flow rule delete it
		    		  if(match.get(MatchField.ETH_SRC).equals(device.getMACAddress()) || 
		    				  match.get(MatchField.ETH_DST).equals(device.getMACAddress()))
		    		  {
		    			  noSwitchtoconfig++;
		    			  System.out.println("match found!!!!! at switch:"+ sw.getId());
		    			  Match.Builder mb = sw.getOFFactory().buildMatch();
			    			mb.setExact(MatchField.ETH_SRC, match.get(MatchField.ETH_DST))                         
			    			.setExact(MatchField.ETH_DST, match.get(MatchField.ETH_SRC));
			    			if (match.get(MatchField.VLAN_VID) != null) {
			    				mb.setExact(MatchField.VLAN_VID, match.get(MatchField.VLAN_VID));                    
			    			}
			    			this.writeFlowMod(sw, OFFlowModCommand.DELETE, OFBufferId.NO_BUFFER, mb.build(), match.get(MatchField.IN_PORT));
		    		  }
		    			
		    	  }
		    }
	}
	
	 /**
		 * Writes a OFFlowMod to a switch.
		 * @param sw The switch tow rite the flowmod to.
		 * @param command The FlowMod actions (add, delete, etc).
		 * @param bufferId The buffer ID if the switch has buffered the packet.
		 * @param match The OFMatch structure to write.
		 * @param outPort The switch port to output it to.
		 */
		private void writeFlowMod(IOFSwitch sw, OFFlowModCommand command, OFBufferId bufferId,
				Match match, OFPort outPort) {
			
			OFFlowMod.Builder fmb;
			if (command == OFFlowModCommand.DELETE) {
				fmb = sw.getOFFactory().buildFlowDelete();
			} else {
				fmb = sw.getOFFactory().buildFlowAdd();
			}
			fmb.setMatch(match);
			U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0); 
			fmb.setCookie(cookie)
			.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
			.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
			.setBufferId(OFBufferId.NO_BUFFER)
			.setPriority(flow_priority);
			fmb.setOutPort((command == OFFlowModCommand.DELETE) ? OFPort.ANY : outPort);
			Set<OFFlowModFlags> sfmf = new HashSet<OFFlowModFlags>();
			if (command != OFFlowModCommand.DELETE) {
				sfmf.add(OFFlowModFlags.SEND_FLOW_REM);
			}
			fmb.setFlags(sfmf);


			// set the ofp_action_header/out actions:
				// from the openflow 1.0 spec: need to set these on a struct ofp_action_output:
			// uint16_t type; /* OFPAT_OUTPUT. */
			// uint16_t len; /* Length is 8. */
			// uint16_t port; /* Output port. */
			// uint16_t max_len; /* Max length to send to controller. */
			// type/len are set because it is OFActionOutput,
			// and port, max_len are arguments to this constructor
			List<OFAction> al = new ArrayList<OFAction>();
			al.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffFFffFF).build());
			fmb.setActions(al);

			if (log.isTraceEnabled()) {
				log.trace("{} {} flow mod {}",
						new Object[]{ sw, (command == OFFlowModCommand.DELETE) ? "deleting" : "adding", fmb.build() });
			}

			//counterFlowMod.increment();

			// and write it out
			sw.write(fmb.build());
		}


	public void tempdeployflow(IDevice device) {
		// TODO Auto-generated method stub
	///// find CN 
		deleteflow(device);
					IDevice CN = findCN(device);
					SwitchPort NewMN = null;
		//find  MN new location
					if(mactoattachment.containsKey(device.getDeviceKey()))
					{
						int noa = mactoattachment.get(device.getDeviceKey()).size();
						if( noa > 1)
						{
							NewMN = mactoattachment.get(device.getDeviceKey()).get(noa-1);
						}
					}
					if(CN != null && NewMN != null)
					{
						try {
							createfile("CN is not null\n", fileflow);
							createfile("calculate new path", fileflow);
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						// find path between CN and MN New location
						SwitchPort cn =CN.getAttachmentPoints()[0];
						Route route = findroute(cn.getSwitchDPID(), 
								cn.getPort(),
								NewMN.getSwitchDPID(),
								NewMN.getPort());
						if(route != null)
						{
							try {
								createfile("routeee CN to MN is not null\n", fileflow);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
							noSwitchtoconfig = noSwitchtoconfig + (route.getPath().size())/2;
							deployflow(route.getPath(), device, CN);	
						}
					}
					movingdevice=null;
		
	}
	
	private void deployflow(List<NodePortTuple> route, IDevice desti, IDevice src) {
		// TODO Auto-generated method stub
		if(route != null)
		{
			try {
				createfile("deploying flowsss\n", fileflow);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
			for (int indx = route.size() - 1; indx > 0; indx -= 2) {
				// indx and indx-1 will always have the same switch DPID.
				DatapathId switchDPID = route.get(indx).getNodeId();
				System.out.println("TEST: "+switchDPID);
				IOFSwitch sw = switchService.getSwitch(switchDPID);
				Match m = createMatch(sw, desti,src);  // device which is moving is destination for pkts coming from CN
               
				if(sw != null)
				{
					noFlows++;
					try {
						createfile("deploy flow: switch=" + sw  + "\n", fileflow);
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					OFFlowMod.Builder fmb;
					fmb = sw.getOFFactory().buildFlowAdd();

					OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
					List<OFAction> actions = new ArrayList<OFAction>();	
					Match.Builder mb = MatchUtils.createRetentiveBuilder(m);

					// set input and output ports on the switch
					OFPort outPort = route.get(indx).getPortId();
					OFPort inPort = route.get(indx - 1).getPortId();
					mb.setExact(MatchField.IN_PORT, inPort);
					aob.setPort(outPort);
					aob.setMaxLen(Integer.MAX_VALUE);
					actions.add(aob.build());
					/////
					 //store match for deleting further
					this.switchtomatch.AddMatch(sw, mb.build());
					/////
					flow_priority++;
					// compile
					fmb.setMatch(mb.build()) // was match w/o modifying input port
					.setActions(actions)
					.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
					.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
					.setBufferId(OFBufferId.NO_BUFFER)
					.setCookie(cookie)
					.setOutPort(outPort)
					.setPriority(flow_priority);

					try {
						if (log.isTraceEnabled()) {
							log.trace("Pushing Route flowmod routeIndx={} " +
									"sw={} inPort={} outPort={}",
									new Object[] {indx,
									sw,
									fmb.getMatch().get(MatchField.IN_PORT),
									outPort });
						}
						messageDamper.write(sw, fmb.build());
					
							sw.flush();
				} catch (IOException e) {
					log.error("Failure writing flow mod", e);
				}
					try {
						createfile("Flows rule added ---------------meee----------"+ sw+"\n", fileflow);
						createfile("Route::"+ route+"\n", fileflow);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}

			
		}
		}
		
	}
	public Match createMatch(IOFSwitch sw, IDevice desti, IDevice src)
	{
		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.ETH_DST, desti.getMACAddress());
		mb.setExact(MatchField.ETH_SRC, src.getMACAddress());
		return mb.build();
	}
//////////find route  
public Route findroute(DatapathId sw1, OFPort port1, DatapathId sw2, OFPort port2)
{	//System.out.println("my routeeeeeeeeeeeeeeeeeeee:641");
	RouteId rid = new RouteId(sw1,sw2);
	   if(islink(sw1, sw2))
	   {
		   List<NodePortTuple> route = new ArrayList<NodePortTuple>();
		   route.add(new NodePortTuple(sw1,port1));
		   List<NodePortTuple> temp = linktupple(sw1, sw2);
		   route.add(temp.get(0));
		   route.add(temp.get(1));
		   route.add(new NodePortTuple(sw2,port2));
		   return new Route(rid, route);
	   }
	   if(sw1.equals(sw2))
		   return null;
	   //System.out.println("my routeeeeeeeeeeeeeeeeeeee:647");
	   int path[] =findPath(sw1,sw2);
	  // System.out.println("my routeeeeeeeeeeeeeeeeeeee:649");
	   if(path == null)
		   return null;
	   
	   List<NodePortTuple> p = convertTopath(sw1, port1, sw2, port2, path );
	   //System.out.println("my routeeeeeeeeeeeeeeeeeeee:651");
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
	   Map<Link,LinkInfo> links = linkdiscoveryservices.getLinks();
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
/// find shortest path using DFS
public int [] findPath(DatapathId s, DatapathId d)
{
	   int src, desti;
	   if(switchmap.containsKey(s) && switchmap.containsKey(d))
	   {
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
			createfile("converted path in to sw-port:"+ route +"\n", fileflow);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} 
	return route;
}
//find reverse match int to DPID
	private DatapathId finddpid(int i)
	{
		for(Map.Entry<DatapathId, Integer> entry: switchmap.entrySet())
		{
			if(entry.getValue().equals(i))
				return entry.getKey();
		}
		return null;
	}

	private Link getlink(DatapathId src, DatapathId desti)
	{
		Map<DatapathId, Set<Link>> linkmap = linkdiscoveryservices.getSwitchLinks();
		Set<Link> srclink = linkmap.get(src);
		for(Link l: srclink)
		{
			if(l.getDst().equals(desti))
				return l;
		}
		return null;
	}
	
	private List<NodePortTuple> linktupple(DatapathId src , DatapathId desti) {
		// TODO Auto-generated method stub
		   Map<Link,LinkInfo> links = linkdiscoveryservices.getLinks();
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
}