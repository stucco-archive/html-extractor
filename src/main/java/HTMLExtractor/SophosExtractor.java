package HTMLExtractor;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
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
	
	private JSONObject extract(String summary, String details){
		
		JSONObject graph = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();
		
		JSONObject vertex = new JSONObject();
		
		////////////////////////////////////
		//process the "summary" page
		Document doc = Jsoup.parse(summary);
		Element content = doc.getElementsByClass("tertiaryBump").first();
		if(debug){
			System.out.println(content.html());
			System.out.println("=========");
		}
		
		//get the title, set up name & other known fields
		Element titleDiv = content.getElementsByClass("marqTitle").first();
		if(debug){
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
		vertex.put("addedDate", convertTimestamp(addedDate));
		Element rowTwo = titleDiv.getElementsByTag("tr").get(1);
		String type = rowTwo.child(1).text();
		vertex.put("type", type);
		String modifiedDate = rowTwo.child(3).text();
		vertex.put("modifiedDate", convertTimestamp(modifiedDate));
		
		Element secondaryDiv = doc.getElementById("secondaryContent");
		//TODO handle secondary div
		
		////////////////////////////////////
		//process the "details" page
		doc = Jsoup.parse(details);
		content = doc.getElementById("asdf");//TODO
		//vertex.put("description", content.text());
		
	    
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    return graph;
	}

}
