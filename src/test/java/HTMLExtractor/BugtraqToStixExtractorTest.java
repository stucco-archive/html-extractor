package HTMLExtractor;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
						
import static org.junit.Assert.*;

/**
 * Unit test for simple App.
 */			
public class BugtraqToStixExtractorTest {
	
	private Map<String,String> loadContent(int entryNum, boolean localMode) throws IOException{
		Map<String,String> pageContent = new HashMap<String,String>();
		String filePath = "./testData/bugtraq/";
		Charset charset = Charset.defaultCharset();
		if(localMode){
			File infoFD = new File(filePath + entryNum + ".info.html");
			String info = FileUtils.readFileToString(infoFD, charset);
			pageContent.put("info", info);
			
			File discussionFD = new File(filePath + entryNum + ".discussion.html");
			String discussion = FileUtils.readFileToString(discussionFD, charset);
			pageContent.put("discussion", discussion);
			
			File exploitFD = new File(filePath + entryNum + ".exploit.html");
			String exploit = FileUtils.readFileToString(exploitFD, charset);
			pageContent.put("exploit", exploit);
			
			File solutionFD = new File(filePath + entryNum + ".solution.html");
			String solution = FileUtils.readFileToString(solutionFD, charset);
			pageContent.put("solution", solution);
			
			File referencesFD = new File(filePath + entryNum + ".references.html");
			String references = FileUtils.readFileToString(referencesFD, charset);
			pageContent.put("references", references);
		}
		else{
			URL u;
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/info");
			pageContent.put("info", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/discussion");
			pageContent.put("discussion", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/exploit");
			pageContent.put("exploit", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/solution");
			pageContent.put("solution", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/references");
			pageContent.put("references", IOUtils.toString(u));
		}
		return pageContent;
	}
	
	/**
	 * Tests conversion for item 2222
	 */
	@Test
	public void testConvert_2222()	{

		int entryNum = 2222;
		boolean localMode = true;
		String info, discussion, exploit, solution, references;
		
		try {
			Map<String,String> pageContent = loadContent(entryNum, localMode);
			info = pageContent.get("info");
			discussion = pageContent.get("discussion");
			exploit = pageContent.get("exploit");
			solution = pageContent.get("solution");
			references = pageContent.get("references");
			
			//TODO maybe add a BugtraqExtractor(Map)?
			BugtraqToStixExtractor bugtraqExt = new BugtraqToStixExtractor(info, discussion, exploit, solution, references);
			STIXPackage receivedPackage = bugtraqExt.getStixPackage();
			
		//	System.out.println(receivedPackage.toXMLString(true));		    

		    String expectedVerts = 
			    "<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
			    "<stix:STIX_Package " +
			    "    id=\"stucco:bugtraq-b843cbb8-4a3c-4743-8585-71534f787040\" " +
			    "    timestamp=\"2015-07-09T21:53:22.948Z\" " +
			    "    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\" " +
			    "    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
			    "    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
			    "    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
			    "    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
			    "    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"stucco\"> " +
			    "    <stix:STIX_Header> " +
			    "        <stix:Title>Bugtraq</stix:Title> " +
			    "    </stix:STIX_Header> " +
			    "    <stix:Exploit_Targets> " +
			    "        <stixCommon:Exploit_Target " +
			    "            id=\"stucco:bugtraq-5a3fefea-8faa-4eed-adcb-2a953e6bd788\" " +
			    "            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
			    "            <et:Vulnerability> " +
			    "                <et:Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability SSH is a package designed to encrypt traffic between two end points using the IETF specified SSH protocol. The SSH1 package is distributed and maintained by SSH Communications Security. A problem exists which could allow the discovery of the secret key used to encrypt traffic on the local host. When using SUN-DES-1 to share keys with other hosts on the network to facilitate secure communication via protocols such as NFS and NIS+, the keys are shared between hosts using the private key of the user and a cryptographic algorithm to secure the contents of the key, which is stored on the NIS+ primary. The problem occurs when the key is encrypted with the SUN-DES-1 magic phrase prior to having done a keylogin (the keyserv does not have the users DH private key). A design flaw in the software that shares the key with the NIS+ master will inconsistently return the correct value for an attempted keyshare that has failed. A step in the private key encryption process is skipped, and the users private key is then encrypted only with the public key of the target server and the SUN-DES-1 magic phrase, a phrase that is guessable due to the way it is generated. A user from the same host can then execute a function that returns another users magic phrase, and use this to decrypt the private key of the victim. This makes it possible for a user with malicious intent to gain knowledge of a users secret key, and decrypt sensitive traffic between two hosts, with the possibility of gaining access and elevated privileges on the hosts and/or NIS+ domain. This reportedly affects the SSH2 series of the software package.</et:Description> " +
			    "                <et:Short_Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability</et:Short_Description> " +
			    "                <et:Source>Bugtraq</et:Source> " +
			    "                <et:Discovered_DateTime>2001-01-15T19:00:00.000-05:00</et:Discovered_DateTime> " +
			    "                <et:Affected_Software> " +
			    "                    <et:Affected_Software> " +
			    "                        <stixCommon:Observable> " +
			    "                            <cybox:Object> " +
			    "                                <cybox:Properties xsi:type=\"ProductObj:ProductObjectType\"> " +
			    "                                    <ProductObj:Product>SSH Communications Security SSH 1.2.30</ProductObj:Product> " +
			    "                                </cybox:Properties> " +
			    "                            </cybox:Object> " +
			    "                        </stixCommon:Observable> " +
			    "                    </et:Affected_Software> " +
			    "                    <et:Affected_Software> " +
			    "                        <stixCommon:Observable> " +
			    "                            <cybox:Object> " +
			    "                                <cybox:Properties xsi:type=\"ProductObj:ProductObjectType\"> " +
			    "                                    <ProductObj:Product>SSH Communications Security SSH 1.2.29</ProductObj:Product> " +
			    "                                </cybox:Properties> " +
			    "                            </cybox:Object> " +
			    "                        </stixCommon:Observable> " +
			    "                    </et:Affected_Software> " +
			    "                    <et:Affected_Software> " +
			    "                        <stixCommon:Observable> " +
			    "                            <cybox:Object> " +
			    "                                <cybox:Properties xsi:type=\"ProductObj:ProductObjectType\"> " +
			    "                                    <ProductObj:Product>SSH Communications Security SSH 1.2.28</ProductObj:Product> " +
			    "                                </cybox:Properties> " +
			    "                            </cybox:Object> " +
			    "                        </stixCommon:Observable> " +
			    "                    </et:Affected_Software> " +
			    "                    <et:Affected_Software> " +
			    "                        <stixCommon:Observable> " +
			    "                            <cybox:Object> " +
			    "                                <cybox:Properties xsi:type=\"ProductObj:ProductObjectType\"> " +
			    "                                    <ProductObj:Product>SSH Communications Security SSH 1.2.27</ProductObj:Product> " +
			    "                                </cybox:Properties> " +
			    "                            </cybox:Object> " +
			    "                        </stixCommon:Observable> " +
			    "                    </et:Affected_Software> " +
			    "                </et:Affected_Software> " +
			    "            </et:Vulnerability> " +
			    "            <et:Potential_COAs> " +
			    "                <et:Potential_COA> " +
			    "                    <stixCommon:Course_Of_Action xsi:type=\"coa:CourseOfActionType\"> " +
			    "                        <coa:Description>Solution: Patches available: SSH Communications Security SSH 1.2.27 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.28 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.29 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.30 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc</coa:Description> " +
			    "                    </stixCommon:Course_Of_Action> " +
			    "                </et:Potential_COA> " +
			    "            </et:Potential_COAs> " +
			    "        </stixCommon:Exploit_Target> " +
			    "    </stix:Exploit_Targets> " +
			    "</stix:STIX_Package> ";

		    String expectedEdges = "[{" + 
		    		  "  '_type': 'edge'," +
		    		  "  'outVType': 'software',"+
		    		  "  'source': 'Bugtraq',"+
		    		  "  '_id': 'SSH Communications Security SSH 1.2.30_hasVulnerability_Bugtraq_2222',"+
		    		  "  'description': 'SSH Communications Security SSH 1.2.30 has vulnerability Bugtraq ID 2222',"+
		    		  "  '_label': 'hasVulnerability',"+
		    		  "  '_outV': 'SSH Communications Security SSH 1.2.30',"+
		    		  "  '_inV': 'Bugtraq_2222',"+
		    		  "  'inVType': 'vulnerability'"+
			    	  "},"+
			    	  "{"+
			    	  "  '_type': 'edge',"+
			    	  "  'outVType': 'software',"+
			    	  "  'source': 'Bugtraq',"+
			    	  "  '_id': 'SSH Communications Security SSH 1.2.29_hasVulnerability_Bugtraq_2222',"+
			    	  "  'description': 'SSH Communications Security SSH 1.2.29 has vulnerability Bugtraq ID 2222',"+
			    	  "  '_label': 'hasVulnerability',"+
			    	  "  '_outV': 'SSH Communications Security SSH 1.2.29',"+
			    	  "  '_inV': 'Bugtraq_2222',"+
			    	  "  'inVType': 'vulnerability'"+
				      "},"+
				      "{"+
			    	  "  '_type': 'edge',"+
			    	  "  'outVType': 'software',"+
			    	  "  'source': 'Bugtraq',"+
			    	  "  '_id': 'SSH Communications Security SSH 1.2.28_hasVulnerability_Bugtraq_2222',"+
			    	  "  'description': 'SSH Communications Security SSH 1.2.28 has vulnerability Bugtraq ID 2222',"+
			    	  "  '_label': 'hasVulnerability',"+
			    	  "  '_outV': 'SSH Communications Security SSH 1.2.28',"+
			    	  "  '_inV': 'Bugtraq_2222',"+
			    	  "  'inVType': 'vulnerability'"+
				   	  "},"+
				   	  "{"+
			    	  "  '_type': 'edge',"+
			    	  "  'outVType': 'software',"+
			    	  "  'source': 'Bugtraq',"+
			    	  "  '_id': 'SSH Communications Security SSH 1.2.27_hasVulnerability_Bugtraq_2222',"+
			    	  "  'description': 'SSH Communications Security SSH 1.2.27 has vulnerability Bugtraq ID 2222',"+
			    	  "  '_label': 'hasVulnerability',"+
			    	  "  '_outV': 'SSH Communications Security SSH 1.2.27',"+
			    	  "  '_inV': 'Bugtraq_2222',"+
			    	  "  'inVType': 'vulnerability'"+
		    		  "}]";
		    											
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
										
			assertTrue(bugtraqExt.validate(receivedPackage));
		
			ExploitTarget etReceived = (ExploitTarget)receivedPackage.getExploitTargets().getExploitTargets().get(0);	
			ExploitTarget etExpected = (ExploitTarget)expectedPackage.getExploitTargets().getExploitTargets().get(0);	
					
			VulnerabilityType vulnReceived = etReceived.getVulnerabilities().get(0);
			VulnerabilityType vulnExpected = etExpected.getVulnerabilities().get(0);
		
			assertEquals(vulnReceived, vulnExpected);
										

		} catch (IOException e)	{
			e.printStackTrace();
		}
	}

	/**
	 * Tests conversion for item 72838
	 */
	@Test
	public void testConvert_72838()
	{
		int entryNum = 72838;
		boolean localMode = true;
		String info, discussion, exploit, solution, references;
		
		try {
			Map<String,String> pageContent = loadContent(entryNum, localMode);
			info = pageContent.get("info");
			discussion = pageContent.get("discussion");
			exploit = pageContent.get("exploit");
			solution = pageContent.get("solution");
			references = pageContent.get("references");
			
			BugtraqToStixExtractor bugtraqExt = new BugtraqToStixExtractor(info, discussion, exploit, solution, references);
			STIXPackage receivedPackage = bugtraqExt.getStixPackage();
						
		//	System.out.println(receivedPackage.toXMLString(true));		    

		     	String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:bugtraq-c203648b-dbe3-4ec1-a03f-b7f148335db9\" " +
				"    timestamp=\"2015-07-09T21:53:30.235Z\" " +
				"    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"stucco\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Bugtraq</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:bugtraq-08391dce-8fcf-4ef0-8081-189abf733c17\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Vulnerability> " +
				"                <et:Description>WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified by CLSID's: 359742AF-BF34-4379-A084-B7BF0E5F34B0 4E14C449-A61A-4BF7-8082-65A91298A6D8 5A216ADB-3009-4211-AB77-F1857A99482C An attacker can exploit these issues to execute arbitrary code in the context of the application, usually Internet Explorer, using the ActiveX control.Failed attacks will likely cause denial-of-service conditions.</et:Description> " +
				"                <et:Short_Description>WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities</et:Short_Description> " +
				"                <et:CVE_ID>CVE-2015-2098</et:CVE_ID> " +
				"                <et:Source>Bugtraq</et:Source> " +
				"                <et:Discovered_DateTime>2015-03-26T20:00:00.000-04:00</et:Discovered_DateTime> " +
				"                <et:References> " +
				"                    <stixCommon:Reference>http://support.microsoft.com/kb/240797</stixCommon:Reference> " +
				"                </et:References> " +
				"            </et:Vulnerability> " +
				"            <et:Potential_COAs> " +
				"                <et:Potential_COA> " +
				"                    <stixCommon:Course_Of_Action xsi:type=\"coa:CourseOfActionType\"> " +
				"                        <coa:Description>Solution: Currently, we are not aware of any vendor-supplied patches. If you feel we are in error or are aware of more recent information, please mail us at: vuldb@securityfocus.com.</coa:Description> " +
				"                    </stixCommon:Course_Of_Action> " +
				"                </et:Potential_COA> " +
				"            </et:Potential_COAs> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"</stix:STIX_Package> ";
								
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
										
			assertTrue(bugtraqExt.validate(receivedPackage));
		
			ExploitTarget etReceived = (ExploitTarget)receivedPackage.getExploitTargets().getExploitTargets().get(0);	
			ExploitTarget etExpected = (ExploitTarget)expectedPackage.getExploitTargets().getExploitTargets().get(0);	
					
			VulnerabilityType vulnReceived = etReceived.getVulnerabilities().get(0);
			VulnerabilityType vulnExpected = etExpected.getVulnerabilities().get(0);
		
			assertEquals(vulnReceived, vulnExpected);

		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

}
