package net.floodlightcontroller.mobilityprotocols;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.routing.Route;

public interface MobilityService extends IFloodlightService {

	public Route findroute(DatapathId src, OFPort srcport, DatapathId dst, OFPort dstport);
	
}
