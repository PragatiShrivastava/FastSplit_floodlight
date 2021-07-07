package net.floodlightcontroller.forwarding;
import java.util.ArrayList;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.match.Match;

import net.floodlightcontroller.core.IOFSwitch;
public class SwitchtoMatch {
	private Map<IOFSwitch,ArrayList<Match>> MapSwitchtomatch;
	
	public SwitchtoMatch(Map<IOFSwitch,ArrayList<Match>> stmmap)
	{
		MapSwitchtomatch = stmmap;
	}
	
	protected void AddMatch(IOFSwitch sw, Match m )
	{
		if(!MapSwitchtomatch.containsKey(sw))
		{
			MapSwitchtomatch.put(sw, new ArrayList<Match>());
		}
		MapSwitchtomatch.get(sw).add(m);
	}
	protected ArrayList<Match> GetMatch(IOFSwitch sw)
	{
		if(MapSwitchtomatch.containsKey(sw))
			return MapSwitchtomatch.get(sw);
		
		return null;
	}
	
	protected void DeleteMatch(IOFSwitch sw, Match m)
	{
		if(MapSwitchtomatch.containsKey(sw))
			if(MapSwitchtomatch.get(sw).contains(m))
					MapSwitchtomatch.get(sw).remove(m);
	}
}
