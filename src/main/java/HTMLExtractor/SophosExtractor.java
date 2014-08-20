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

public class SophosExtractor extends HTMLExtractor{
	
	private JSONObject graph;
	private static boolean debug = true;
	private static boolean verboseDebug = false;

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
		if(verboseDebug){
			System.out.println(content.html());
			System.out.println("=========");
		}
		
		//get the title, set up name & other known fields
		Element titleDiv = content.getElementsByClass("marqTitle").first();
		if(verboseDebug){
			System.out.println(titleDiv.html());
			System.out.println("=========");
		}
		String vertexName = titleDiv.getElementsByTag("h1").first().text();
		if(debug){
			System.out.println("Name: " + vertexName);
			System.out.println("=========");
		}
		vertex.put("name", vertexName);
		vertex.put("_id", vertexName);
		vertex.put("_type", "vertex");
		vertex.put("vertexType", "malware");
		vertex.put("source", "Sophos");
		
		//rest of that marqTitle div
		Element rowOne = titleDiv.getElementsByTag("tr").first();
		String category = rowOne.child(1).text();
		vertex.put("category", category);
		String addedDate = rowOne.child(3).text();
		if(!addedDate.equals("")){//some don't list dates, not sure why
			vertex.put("signatureDate", convertTimestamp(addedDate));
			vertex.put("discoveryDate", convertTimestamp(addedDate));
		}
		Element rowTwo = titleDiv.getElementsByTag("tr").get(1);
		String type = rowTwo.child(1).text();
		vertex.put("type", type);
		String modifiedDate = rowTwo.child(3).text();
		if(!modifiedDate.equals(""))
			vertex.put("modifiedDate", convertTimestamp(modifiedDate));
		Element rowThree = titleDiv.getElementsByTag("tr").get(2);
		String prevalence = rowThree.child(1).getElementsByTag("img").first().attr("alt");
		vertex.put("prevalence", prevalence); //TODO: convert labels into int levels, or similar?
		if(debug){
			System.out.println("Prevalence: " + prevalence);
			System.out.println("=========");
		}
		
		//handle secondary div
		Element secondaryDiv = doc.getElementsByClass("secondaryContent").first();
		if(verboseDebug){
			System.out.println(secondaryDiv.html());
			System.out.println("=========");
		}
		Elements aliasItems = secondaryDiv.getElementsByClass("aliases");
		if(aliasItems != null && aliasItems.size() > 0){ //some don't have any listed.
			aliasItems = aliasItems.first().children();
			if(verboseDebug){
				System.out.println(aliasItems.outerHtml());
				System.out.println("=========");
			}
			List<String> aliasList = new ArrayList<String>();
			for(int i=0; i<aliasItems.size(); i++){
				aliasList.add(aliasItems.get(i).text());
			}
			//TODO: how best to handle aliases in the long term?
			vertex.put("aliases", aliasList);
			if(debug){
				System.out.println("Found " + aliasList.size() + " items in aliasList:");
				for(int i=0; i<aliasList.size(); i++){
					System.out.println(aliasList.get(i));
				}
				System.out.println("=========");
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
		if(debug){
			if(affectedHeading != null){
				System.out.println("Platform: " + platformName);
				System.out.println("=========");
			}
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
		//TreeSet<String> filetype = new TreeSet<String>();
		long firstSeen;
		boolean runtimeAnalysisFound = false;
		for(int i=0; i<h4headings.size(); i++){
			curr = h4headings.get(i);
			nextSibling = curr.nextElementSibling();
			if(curr.text().equals("File Information") && nextSibling.tagName().equals("dl")){
				if(verboseDebug) System.out.println("Found a file info table: \n" + nextSibling.html());
				currTableContents = dlToMap(nextSibling); //TODO code below will NPE if this is null.  Fine while testing, should fix before using. 
				if(debug) System.out.println("Extracted map from file info table: " + currTableContents);
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
				if(debug) System.out.println("'Runtime Analysis' section found");
			}else if(curr.text().equals("Other vendor detection") && nextSibling.tagName().equals("dl")){
				currTableContents = dlToMap(nextSibling); //TODO code below will NPE if this is null.  Fine while testing, should fix before using. 
				if(debug) System.out.println("Extracted map from 'other vendor detection table: " + currTableContents);
				JSONArray aliasArr = vertex.optJSONArray("aliases");
				Set<String> aliasSet = JSONArrayToSet(aliasArr);
				Set<String> keys = currTableContents.keySet();
				Iterator<String> keysIter = keys.iterator();
				while(keysIter.hasNext()){
					aliasSet.add(currTableContents.get(keysIter.next()));
				}
				if(debug) System.out.println("now know aliases: " + aliasSet);
				vertex.put("aliases", aliasSet);
			}else{
				if(debug) System.out.println("Unexpected H4 Found: " + curr.text());
			}
			
		}
		if(debug) System.out.println("=========");

		//use what you've learned.
		//if(size != null && size.size() > 0){} //not keeping this one
		if(sha1 != null && sha1.size() > 0){
			vertex.put("knownSha1Hashes", sha1);
		}
		if(md5 != null && md5.size() > 0){
			vertex.put("knownMD5Hashes", md5);
		}
		//if(crc32 != null && crc32.size() > 0){} //not keeping this one
		if(filetype != null && filetype.size() > 0){
			vertex.put("knownFileTypes", filetype);
		}
		
		//TODO: handle the "Runtime Analysis" sections...
		if(runtimeAnalysisFound){
			if(debug){
				if(debug) System.out.println("'Runtime Analysis' section found");
				if(debug) System.out.println("=========");
			}
		}
		
		//TODO put some remaining free text in desc?
		//vertex.put("description", content.text());
	    
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    return graph;
	}

}
