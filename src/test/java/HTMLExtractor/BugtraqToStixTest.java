package HTMLExtractor;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import org.mitre.stix.stix_1.STIXPackage;

import static org.junit.Assert.*;

/**
 * Unit test for simple App.
 */
public class BugtraqToStixTest {
				
	/**
	 * Tests conversion from JSON to STIX
	 */
	@Test
	public void testJsonToStix()	{
		
		String verts = "[{"+
		    		  "  'vertexType': 'software'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  '_id': 'SSH Communications Security SSH 1.2.30'," +
		    		  "  'name': 'SSH Communications Security SSH 1.2.30'" +
				  	  "},"+
				   	  "{"+
		    		  "  'vertexType': 'software'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  '_id': 'SSH Communications Security SSH 1.2.29'," +
		    		  "  'name': 'SSH Communications Security SSH 1.2.29'" +
			    	  "},"+
			    	  "{"+
		    		  "  'vertexType': 'software'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  '_id': 'SSH Communications Security SSH 1.2.28'," +
		    		  "  'name': 'SSH Communications Security SSH 1.2.28'" +
			    	  "},"+
			    	  "{"+
		    		  "  'vertexType': 'software'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  '_id': 'SSH Communications Security SSH 1.2.27'," +
		    		  "  'name': 'SSH Communications Security SSH 1.2.27'" +
			    	  "},"+
			    	  "{"+
		    		  "  'accessVector': 'LOCAL'," +
		    		  "  'Credit': 'This vulnerability was discovered by Richard Silverman &lt;slade@shore.net&gt;, and first announced by SSH Communications Security in an advisory posted to Bugtraq on January 16, 2001.'," +
		    		  "  'class': 'Design Error'," +
		    		  "  'CVE': 'CVE-2000-1999'," +
		    		  "  'solution': 'Solution: Patches available: SSH Communications Security SSH 1.2.27 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.28 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.29 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.30 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc'," +
		    		  "  'exploit': 'This exploit was contributed by Richard Silverman <slade@shore.net> : /data/vulnerabilities/exploits/ssh1-exploit.c'," +
		    		  "  'modifiedDate': 979603200000," +
		    		  "  'vertexType': 'vulnerability'," +
		    		  "  '_type': 'vertex'," +														
		    		  "  'references': [\"http://service.software.ibm.com/rs6k/fixes.html\",\"http://service.software.ibm.com/support/rs6000\"],"+
		    		  "  '_id': 'Bugtraq_2222'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  'shortDescription': 'SSH Secure-RPC Weak Encrypted Authentication Vulnerability'," +
		    		  "  'description': 'SSH Secure-RPC Weak Encrypted Authentication Vulnerability SSH is a package designed to encrypt traffic between two end points using the IETF specified SSH protocol. The SSH1 package is distributed and maintained by SSH Communications Security. A problem exists which could allow the discovery of the secret key used to encrypt traffic on the local host. When using SUN-DES-1 to share keys with other hosts on the network to facilitate secure communication via protocols such as NFS and NIS+, the keys are shared between hosts using the private key of the user and a cryptographic algorithm to secure the contents of the key, which is stored on the NIS+ primary. The problem occurs when the key is encrypted with the SUN-DES-1 magic phrase prior to having done a keylogin (the keyserv does not have the users DH private key). A design flaw in the software that shares the key with the NIS+ master will inconsistently return the correct value for an attempted keyshare that has failed. A step in the private key encryption process is skipped, and the users private key is then encrypted only with the public key of the target server and the SUN-DES-1 magic phrase, a phrase that is guessable due to the way it is generated. A user from the same host can then execute a function that returns another users magic phrase, and use this to decrypt the private key of the victim. This makes it possible for a user with malicious intent to gain knowledge of a users secret key, and decrypt sensitive traffic between two hosts, with the possibility of gaining access and elevated privileges on the hosts and/or NIS+ domain. This reportedly affects the SSH2 series of the software package.'," +
		    		  "  'name': 'Bugtraq ID 2222'," +
		    		  "  'Vulnerable': [" +
		    		  "    'SSH Communications Security SSH 1.2.30'," +
		    		  "    'SSH Communications Security SSH 1.2.29'," +
		    		  "    'SSH Communications Security SSH 1.2.28'," +
		    		  "    'SSH Communications Security SSH 1.2.27'" +
		    		  "  ]," +
		    		  "  'Not_Vulnerable': []," +
		    		  "  'publishedDate': 979603200000," +
			    	  "}]";
												
		BugtraqExtractor bugtraqExt = new BugtraqExtractor();
		JSONObject graph = new JSONObject();
				    		
		JSONArray vertsArray = new JSONArray(verts);
		graph.put("vertices", vertsArray);
		STIXPackage stixPackage = bugtraqExt.jsonToStix(graph);  
		System.out.println(stixPackage.toXMLString(true));  
		assertTrue(bugtraqExt.validate(stixPackage));
	}										
	
	/**
	 * Tests conversion from JSON to STIX with invalid CVE
	 */
	@Test
	public void testStixValidation() {
		
		String verts = "[{"+
		    		  "  'accessVector': 'LOCAL'," +
		    		  "  'Credit': 'This vulnerability was discovered by Richard Silverman &lt;slade@shore.net&gt;, and first announced by SSH Communications Security in an advisory posted to Bugtraq on January 16, 2001.'," +
		    		  "  'class': 'Design Error'," +
		    		  "  'CVE': 'CVE-20-1'," +
		    		  "  'solution': 'Solution: Patches available: SSH Communications Security'," +
		    		  "  'exploit': 'This exploit was contributed by Richard Silverman <slade@shore.net> : /data/vulnerabilities/exploits/ssh1-exploit.c'," +
		    		  "  'modifiedDate': 979603200000," +
		    		  "  'vertexType': 'vulnerability'," +
		    		  "  '_type': 'vertex'," +														
		    		  "  'references': [\"http://service.software.ibm.com/rs6k/fixes.html\",\"http://service.software.ibm.com/support/rs6000\"],"+
		    		  "  '_id': 'Bugtraq_2222'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  'shortDescription': 'SSH Secure-RPC Weak Encrypted Authentication Vulnerability'," +
		    		  "  'description': 'SSH Secure-RPC Weak Encrypted Authentication Vulnerability'," +
		    		  "  'name': 'Bugtraq ID 2222'," +
		    		  "  'Vulnerable': [" +
		    		  "    'SSH Communications Security SSH 1.2.30'," +
		    		  "    'SSH Communications Security SSH 1.2.29'," +
		    		  "    'SSH Communications Security SSH 1.2.28'," +
		    		  "    'SSH Communications Security SSH 1.2.27'" +
		    		  "  ]," +
		    		  "  'Not_Vulnerable': []," +
		    		  "  'publishedDate': 979603200000," +
			    	  "}]";
		
		BugtraqExtractor bugtraqExt = new BugtraqExtractor();
		JSONObject graph = new JSONObject();
		JSONArray vertsArray = new JSONArray(verts);
		graph.put("vertices", vertsArray);
		STIXPackage stixPackage = bugtraqExt.jsonToStix(graph);  
		System.out.println(stixPackage.toXMLString(true));  
		assertFalse(bugtraqExt.validate(stixPackage));
		
	}
}
