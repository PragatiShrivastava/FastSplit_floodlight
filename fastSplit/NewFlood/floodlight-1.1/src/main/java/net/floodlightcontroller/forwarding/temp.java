//import net.floodlightcontroller.core.IOFSwitchListener;
//import net.floodlightcontroller.core.PortChangeType;
//
//import org.projectfloodlight.openflow.protocol.OFPortDesc;
//import org.projectfloodlight.openflow.types.DatapathId;
//
// private class switchlistener implements IOFSwitchListener{
//
//		@Override
//		public void switchAdded(DatapathId switchId) {
//			// TODO Auto-generated method stub
//			nos++;
//			System.out.println("switch added----------" + nos);
//			
//		}
//
//		@Override
//		public void switchRemoved(DatapathId switchId) {
//			// TODO Auto-generated method stub
//			
//		}
//
//		@Override
//		public void switchActivated(DatapathId switchId) {
//			// TODO Auto-generated method stub
//			
//		}
//
//		@Override
//		public void switchPortChanged(DatapathId switchId, OFPortDesc port,
//				PortChangeType type) {
//			// TODO Auto-generated method stub
//			System.out.println("*****************switchPortChanged type::"+ type );
//			System.out.println(switchId + "//"+ port.getPortNo());
//			switchportstatus= type;       
//		}
//
//		@Override
//		public void switchChanged(DatapathId switchId) {
//			// TODO Auto-generated method stub
//			
//		}
//    	
//    }
// switchService.addOFSwitchListener(this.slisten);
////listener to switch behaviour
//		private switchlistener slisten;
//		// no of switch added
//				public static int nos=0;
//				 this.slisten = new switchlistener();
//				 
//				 System.out.println("switch STATUS:" + switchportstatus);
//					// device is added to switchport and its up
//					if(switchportstatus.equals(PortChangeType.UP))
//					{
//						initiAttachment(device);
//					}
//					
//					//switch port status
//					private static PortChangeType switchportstatus = PortChangeType.DOWN;
//					