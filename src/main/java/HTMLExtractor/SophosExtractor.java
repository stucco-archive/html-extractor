package HTMLExtractor;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SophosExtractor extends HTMLExtractor{
	
	private JSONObject graph;
	private static final Logger logger = LoggerFactory.getLogger(SophosExtractor.class);

	public SophosExtractor(String summary, String details){
		graph = extract(summary, details);
	}
	
	public JSONObject getGraph() {
		return graph;
	}
	
	private long convertTimestamp(String time)	{ 
		return convertTimestamp(time, "dd MMM yyyy hh:mm:ss (z)");
	}
	
	private long convertShortTimestamp(String time)	{ 
		return convertTimestamp(time + " (GMT)", "yyyy-MM-dd (z)");
	}
	
	private JSONObject extract(String summary, String details){
		
		JSONObject graph = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();
		JSONObject edge;
		
		JSONObject vertex = new JSONObject();
		
		////////////////////////////////////
		//process the "summary" page
		Document doc = Jsoup.parse(summary);
		Element content = doc.getElementsByClass("tertiaryBump").first();
		logger.debug(content.html());
		
		//get the title, set up name & other known fields
		Element titleDiv = content.getElementsByClass("marqTitle").first();
		logger.debug(titleDiv.html());
		String vertexName = titleDiv.getElementsByTag("h1").first().text();
		logger.info("Name: {}", vertexName);
		vertex.put("name", vertexName);
		vertex.put("_id", vertexName);
		vertex.put("_type", "vertex");
		vertex.put("vertexType", "malware");
		vertex.put("source", "Sophos");
		
		//rest of that marqTitle div
		Element rowOne = titleDiv.getElementsByTag("tr").first();
		//doesn't appear "category" is ever very informative...
		//String category = rowOne.child(1).text();
		//vertex.put("category", category);
		String addedDate = rowOne.child(3).text();
		if(!addedDate.equals("")){//some don't list dates, not sure why
			vertex.put("signatureDate", convertTimestamp(addedDate));
			vertex.put("discoveryDate", convertTimestamp(addedDate));
		}
		Element rowTwo = titleDiv.getElementsByTag("tr").get(1);
		String type = rowTwo.child(1).text();
		TreeSet<String> typeSet = new TreeSet<String>();
		typeSet.add(type);
		vertex.put("malwareType", typeSet);
		String modifiedDate = rowTwo.child(3).text();
		if(!modifiedDate.equals(""))
			vertex.put("modifiedDate", convertTimestamp(modifiedDate));
		Element rowThree = titleDiv.getElementsByTag("tr").get(2);
		String prevalence = rowThree.child(1).getElementsByTag("img").first().attr("alt");
		vertex.put("prevalence", prevalence); //TODO: convert labels into int levels, or similar?
		logger.info("Prevalence: {}", prevalence);
		
		//handle secondary div
		Element secondaryDiv = doc.getElementsByClass("secondaryContent").first();
		logger.debug(secondaryDiv.html());
		Elements aliasItems = secondaryDiv.getElementsByClass("aliases");
		if(aliasItems != null && aliasItems.size() > 0){ //some don't have any listed.
			aliasItems = aliasItems.first().children();
			logger.debug(aliasItems.outerHtml());
			List<String> aliasList = new ArrayList<String>();
			for(int i=0; i<aliasItems.size(); i++){
				aliasList.add(aliasItems.get(i).text());
			}
			aliasList.add(vertexName);
			//TODO: how best to handle aliases in the long term?
			TreeSet<String> aliasSet = new TreeSet<String>();
			aliasSet.addAll(aliasList);//make into set, in case duplicates.
			vertex.put("aliases", aliasSet);
			logger.info("Found {} items in aliasList:", aliasList.size());
			for(int i=0; i<aliasList.size(); i++){
				logger.info(aliasList.get(i));
			}
		}
		Elements h3s = secondaryDiv.getElementsByTag("h3");
		Element affectedHeading = null;
		for(int i=0; i<h3s.size(); i++){
			if(h3s.get(i).text().equals("Affected Operating Systems")){
				affectedHeading = h3s.get(i);
				break;
			}
		}
		String platformName = affectedHeading.nextElementSibling().getElementsByTag("img").first().attr("alt");
		vertex.put("platform", platformName);
		if(affectedHeading != null){
			logger.info("Platform: {}", platformName);
		}
		
		////////////////////////////////////
		//process the "details" page
		doc = Jsoup.parse(details);
		content = doc.getElementsByClass("threatDetail").first();
		
		//handle the "File Information" tables
		Elements h4headings = content.getElementsByTag("h4");
		Element curr, nextSibling;
		Map<String,String> currTableContents;
		TreeSet<String> size = new TreeSet<String>();
		TreeSet<String> sha1 = new TreeSet<String>();
		TreeSet<String> md5 = new TreeSet<String>();
		TreeSet<String> crc32 = new TreeSet<String>();
		TreeSet<String> filetype = new TreeSet<String>();
		long firstSeen;
		boolean runtimeAnalysisFound = false;
		for(int i=0; i<h4headings.size(); i++){
			curr = h4headings.get(i);
			nextSibling = curr.nextElementSibling();
			if(curr.text().equals("File Information") && nextSibling.tagName().equals("dl")){
				logger.debug("Found a file info table: \n{}", nextSibling.html());
				currTableContents = dlToMap(nextSibling);  
				if(currTableContents == null){
					logger.error("Could not parse table contents! (file info)");
				}else{
					logger.info("Extracted map from file info table: {}", currTableContents);
					if(currTableContents.containsKey("Size")){
						size.add(currTableContents.get("Size"));
					}
					if(currTableContents.containsKey("SHA-1")){
						sha1.add(currTableContents.get("SHA-1"));
					}
					if(currTableContents.containsKey("MD5")){
						md5.add(currTableContents.get("MD5"));
					}
					if(currTableContents.containsKey("CRC-32")){
						crc32.add(currTableContents.get("CRC-32"));
					}
					if(currTableContents.containsKey("File type")){
						filetype.add(currTableContents.get("File type"));
					}
					if(currTableContents.containsKey("First seen")){
						firstSeen = convertShortTimestamp(currTableContents.get("First seen"));
						if(firstSeen < vertex.getLong("discoveryDate")){
							vertex.put("discoveryDate", firstSeen);
						}
					}
				}
			}else if(curr.text().equals("Runtime Analysis")){
				//could do this here, but it's kind of complicated, better to separate it out...
				runtimeAnalysisFound = true;
				logger.info("Runtime Analysis section found, handling later...");
			}else if(curr.text().equals("Other vendor detection") && nextSibling.tagName().equals("dl")){
				currTableContents = dlToMap(nextSibling); 
				if(currTableContents == null){
					logger.error("Could not parse table contents! (other vendor detection)");
				}else{
					logger.info("Extracted map from 'other vendor detection table: {}", currTableContents);
					JSONArray aliasArr = vertex.optJSONArray("aliases");
					Set<String> aliasSet = JSONArrayToSet(aliasArr);
					Set<String> keys = currTableContents.keySet();
					Iterator<String> keysIter = keys.iterator();
					while(keysIter.hasNext()){
						aliasSet.add(currTableContents.get(keysIter.next()));
					}
					logger.info("  now know aliases: {}", aliasSet);
					vertex.put("aliases", aliasSet);
				}
			}else{
				logger.warn("Unexpected H4 Found: {}", curr.text());
			}
			
		}

		//use what you've learned.
		//if(size.size() > 0){} //not keeping this one
		if(sha1.size() > 0) vertex.put("sha1Hashes", sha1);
		if(md5.size() > 0) vertex.put("md5Hashes", md5);
		//if(crc32.size() > 0){} //not keeping this one
		if(filetype.size() > 0) vertex.put("knownFileTypes", filetype);
		
		//handle the "Runtime Analysis" sections...
		if(runtimeAnalysisFound){
			Element nextNextSibling;
			TreeSet<String> filesCreated = new TreeSet<String>();
			TreeSet<String> filesModified = new TreeSet<String>();
			TreeSet<String> registryKeysCreated = new TreeSet<String>();
			TreeSet<String> registryKeysModified = new TreeSet<String>();
			TreeSet<String> processesCreated = new TreeSet<String>();
			TreeSet<String> ipConnections = new TreeSet<String>();
			TreeSet<String> dnsRequests = new TreeSet<String>();
			TreeSet<String> urlsUsed = new TreeSet<String>();
			for(int i=0; i<h4headings.size(); i++){
				curr = h4headings.get(i);
				nextSibling = curr.nextElementSibling();
				nextNextSibling = nextSibling.nextElementSibling();
				Set<String> newItems;
				if(curr.text().equals("Runtime Analysis")){
					logger.info("'Runtime Analysis' section found");
					while(nextSibling != null && nextSibling.tagName().equals("h5") && 
							nextNextSibling != null && nextNextSibling.tagName().equals("ul")){
						if(nextSibling.text().equals("Dropped Files")){
							//TODO save other fields?  MD5 & etc?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							filesCreated.addAll(newItems);
							logger.info("Dropped Files: {}", newItems);
						}
						else if(nextSibling.text().equals("Copies Itself To")){
							//TODO save other fields?  MD5 & etc?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							filesCreated.addAll(newItems);
							logger.info("Copies Itself To: {}", newItems);
						}
			 		else if(nextSibling.text().equals("Modified Files")){
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							filesModified.addAll(newItems);
							logger.info("Modified Files: {}", newItems);
						}
						else if(nextSibling.text().equals("Registry Keys Created")){
							//TODO save other fields?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							registryKeysCreated.addAll(newItems);
							logger.info("Registry Keys Created: {}", newItems);
						}
						else if(nextSibling.text().equals("Registry Keys Modified")){
							//TODO save other fields?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							registryKeysModified.addAll(newItems);
							logger.info("Registry Keys Modified: {}", newItems);
						}
						else if(nextSibling.text().equals("Processes Created")){
							newItems = ulToSet(nextNextSibling);
							processesCreated.addAll(newItems);
							logger.info("Processes Created: {}", newItems);
						}
						else if(nextSibling.text().equals("IP Connections")){
							newItems = ulToSet(nextNextSibling);
							ipConnections.addAll(newItems);
							logger.info("IP Connections: {}", newItems);
						}
						else if(nextSibling.text().equals("DNS Requests")){
							newItems = ulToSet(nextNextSibling);
							dnsRequests.addAll(newItems);
							logger.info("DNS Requests: {}", newItems);
						}
						else if(nextSibling.text().equals("HTTP Requests")){
							newItems = ulToSet(nextNextSibling);
							urlsUsed.addAll(newItems);
							logger.info("HTTP Requests: {}", newItems);
						}
						else{
							logger.info("Unknown! {}:\n{}", nextSibling.text(), nextNextSibling.outerHtml());
						}
						nextSibling = nextNextSibling.nextElementSibling();
						if(nextSibling != null) nextNextSibling = nextSibling.nextElementSibling();
					}
				}
			}
			if(filesCreated.size() > 0) vertex.put("filesCreated", filesCreated);
			if(filesModified.size() > 0) vertex.put("filesModified", filesModified);
			if(registryKeysCreated.size() > 0) vertex.put("registryKeysCreated", registryKeysCreated);
			if(registryKeysModified.size() > 0) vertex.put("registryKeysModified", registryKeysModified);
			if(processesCreated.size() > 0) vertex.put("processesCreated", processesCreated);
			if(urlsUsed.size() > 0) vertex.put("urlsUsed", urlsUsed);
			
			//handle IP info - build address nodes, port nodes, and any edges as needed
			if(ipConnections.size() > 0){
				for(String ip : ipConnections){
					String ipString, portString;
					JSONObject portVertex = null;
					JSONObject ipVertex = null;
					JSONObject addressVertex = null;
					
					int port;
					try{
						port = getPortFromURL(ip);
					}catch(Exception e){
						logger.warn("Exception when parsing port info from ip string " + ip, e);
						port = -1;
					}
					if(port != -1){
						portString = Integer.toString(port);
						if(ip.endsWith(":"+portString))
							ipString = ip.replace(":"+portString, "");
						else 
							ipString = ip;
						
						portVertex = new JSONObject();
						portVertex.put("name", portString);
						portVertex.put("description", portString);
						portVertex.put("_id", portString);
						portVertex.put("_type", "vertex");
						portVertex.put("vertexType", "port");
						portVertex.put("source", "Sophos");
						vertices.put(portVertex);
					}else{ //shouldn't ever give -1 anyway
						logger.warn("could not find port for ip string {}", ip);
						portString = "unknown";
						ipString = ip;
					}
					
					addressVertex = new JSONObject();
					String addressName = ipString + ":" + portString;
					String desc = ipString + ", port " + portString;
					addressVertex.put("name", addressName);
					addressVertex.put("description", desc);
					addressVertex.put("_id", addressName);
					addressVertex.put("_type", "vertex");
					addressVertex.put("vertexType", "Address");
					addressVertex.put("source", "Sophos");
					vertices.put(addressVertex);
					
					edge = new JSONObject();
					edge.put("_inV", addressName);
					edge.put("_outV", vertex.get("name"));
					edge.put("_id", vertex.get("name") + "_to_" + addressName);
					edge.put("_type", "edge");
					edge.put("inVType", "address");
					edge.put("outVType", "malware");
					edge.put("source", "Sophos");
					edge.put("_label", "communicatesWith");
					edges.put(edge);
					
					if(portVertex != null){
						edge = new JSONObject();
						edge.put("_inV", portString);
						edge.put("_outV", addressName);
						edge.put("_id", addressName + "_to_" + portString);
						edge.put("_type", "edge");
						edge.put("inVType", "port");
						edge.put("outVType", "address");
						edge.put("source", "Sophos");
						edge.put("_label", "hasPort");
						edges.put(edge);
					}
					
					ipVertex = new JSONObject();
					ipVertex.put("name", ipString);
					ipVertex.put("description", ipString);
					ipVertex.put("_id", ipString);
					ipVertex.put("_type", "vertex");
					ipVertex.put("vertexType", "ip");
					ipVertex.put("source", "Sophos");
					vertices.put(ipVertex);
					
					edge = new JSONObject();
					edge.put("_inV", ipString);
					edge.put("_outV", addressName);
					edge.put("_id", addressName + "_to_" + ipString);
					edge.put("_type", "edge");
					edge.put("inVType", "ip");
					edge.put("outVType", "address");
					edge.put("source", "Sophos");
					edge.put("_label", "hasIP");
					edges.put(edge);
				}
			}
			
			//if() vertex.put("dnsRequests", dnsRequests); //TODO: make vertex
			//now handle the DNS info the same way
			if(dnsRequests.size() > 0){
				for(String dns : dnsRequests){
					String dnsString, portString;
					JSONObject portVertex = null;
					JSONObject dnsVertex = null;
					JSONObject addressVertex = null;
					
					int port;
					try{
						port = getPortFromURL(dns);
					}catch(Exception e){
						logger.warn("Exception when parsing port info from dns string " + dns, e);
						port = -1;
					}
					if(port != -1){
						portString = Integer.toString(port);
						if(dns.endsWith(":"+portString))
							dnsString = dns.replace(":"+portString, "");
						else 
							dnsString = dns;
						
						portVertex = new JSONObject();
						portVertex.put("name", portString);
						portVertex.put("description", portString);
						portVertex.put("_id", portString);
						portVertex.put("_type", "vertex");
						portVertex.put("vertexType", "port");
						portVertex.put("source", "Sophos");
						vertices.put(portVertex);
					}else{ //shouldn't ever give -1 anyway
						logger.warn("could not find port for dns string {}", dns);
						portString = "unknown";
						dnsString = dns;
					}
					
					//Note that all other address nodes so far are named ip:port, but this is the best we can do here with the provided info.
					// Note that if any sophos entries have IPs and DNS names, then the IPs will be *in addition* to those DNS names, they will not correspond to those resolved names
					//TODO: if any counterexamples are found, revisit.
					addressVertex = new JSONObject();
					String addressName = dnsString + ":" + portString;
					String desc = dnsString + ", port " + portString;
					addressVertex.put("name", addressName);
					addressVertex.put("description", desc);
					addressVertex.put("_id", addressName);
					addressVertex.put("_type", "vertex");
					addressVertex.put("vertexType", "Address");
					addressVertex.put("source", "Sophos");
					vertices.put(addressVertex);
					
					edge = new JSONObject();
					edge.put("_inV", addressName);
					edge.put("_outV", vertex.get("name"));
					edge.put("_id", vertex.get("name") + "_to_" + addressName);
					edge.put("_type", "edge");
					edge.put("inVType", "address");
					edge.put("outVType", "malware");
					edge.put("source", "Sophos");
					edge.put("_label", "communicatesWith");
					edges.put(edge);
					
					if(portVertex != null){
						edge = new JSONObject();
						edge.put("_inV", portString);
						edge.put("_outV", addressName);
						edge.put("_id", addressName + "_to_" + portString);
						edge.put("_type", "edge");
						edge.put("inVType", "port");
						edge.put("outVType", "address");
						edge.put("source", "Sophos");
						edge.put("_label", "hasPort");
						edges.put(edge);
					}
					
					dnsVertex = new JSONObject();
					dnsVertex.put("name", dnsString);
					dnsVertex.put("description", dnsString);
					dnsVertex.put("_id", dnsString);
					dnsVertex.put("_type", "vertex");
					dnsVertex.put("vertexType", "DNSName");
					dnsVertex.put("source", "Sophos");
					vertices.put(dnsVertex);
					
					edge = new JSONObject();
					edge.put("_inV", dnsString);
					edge.put("_outV", addressName);
					edge.put("_id", addressName + "_to_" + dnsString);
					edge.put("_type", "edge");
					edge.put("inVType", "DNSName");
					edge.put("outVType", "address");
					edge.put("source", "Sophos");
					edge.put("_label", "hasDNSName");
					edges.put(edge);
				}
			}
		}
		
		//TODO put some remaining free text in desc? (Not always present...)
		//vertex.put("description", content.text());
		vertex.put("description", vertexName);
	    
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    return graph;
	}

}
