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
		return convertTimestamp(time, "yyyy-MM-dd");
	}
	
	private JSONObject extract(String summary, String details){
		
		JSONObject graph = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();
		
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
				currTableContents = dlToMap(nextSibling); //TODO code below will NPE if this is null.  Fine while testing, should fix before using. 
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
			}else if(curr.text().equals("Runtime Analysis")){
				//could do this here, but it's kind of complicated, better to separate it out...
				runtimeAnalysisFound = true;
				logger.info("Runtime Analysis section found, handling later...");
			}else if(curr.text().equals("Other vendor detection") && nextSibling.tagName().equals("dl")){
				currTableContents = dlToMap(nextSibling); //TODO code below will NPE if this is null.  Fine while testing, should fix before using. 
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
			TreeSet<String> httpRequests = new TreeSet<String>();
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
							httpRequests.addAll(newItems);
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
			if(ipConnections.size() > 0) vertex.put("ipConnections", ipConnections); //TODO: make vertex
			if(dnsRequests.size() > 0) vertex.put("dnsRequests", dnsRequests); //TODO: make vertex
			if(httpRequests.size() > 0) vertex.put("httpRequests", httpRequests); //TODO: make vertex
		}
		
		//TODO put some remaining free text in desc? (Not always present...)
		//vertex.put("description", content.text());
	    
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    return graph;
	}

}
