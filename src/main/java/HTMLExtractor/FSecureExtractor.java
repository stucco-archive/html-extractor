package HTMLExtractor;

import java.util.ArrayList;
import java.util.Arrays;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
import org.jsoup.select.Elements;

public class FSecureExtractor extends HTMLExtractor{
	
	private JSONObject graph;
	private static boolean debug = true;
	private static boolean verboseDebug = false;
	
	public FSecureExtractor(String pageContent){
		graph = extract(pageContent);
	}
	
	public JSONObject getGraph() {
		return graph;
	}
	
	//TODO: get timestamp from RSS?
	//private long convertTimestamp(String time)	{ 
	//}
	
	//This makes <p><b> text into <h4> text.
	//They are equivalent, but not used consistently between pages.
	protected static void fixSectionHeaders(Elements contents){
		Element curr, replacement;
		Elements currChildren;
		for(int i = contents.size()-1; i>=0; i--){
			curr = contents.get(i);
			if(curr.tagName().equals("p")){
				currChildren = curr.children();
				if(currChildren.size() == 1 && currChildren.get(0).tagName().equalsIgnoreCase("b")){
					replacement = new Element(Tag.valueOf("h4"), "");
					replacement.text(curr.text());
					contents.remove(i);
					contents.add(i, replacement);
				}
			}
		}
	}
	
	private JSONObject extract(String pageContent){
		
		JSONObject graph = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();
		
		JSONObject vertex = new JSONObject();
		
		Document doc = Jsoup.parse(pageContent);
		
		////////////////////////////////////
		//get the title, set up name & other known fields
		Element titleDiv = doc.getElementById("title-page-alt");
		String vertexName = titleDiv.text();
		if(debug){
			System.out.println("Name: " + vertexName);
			System.out.println("=========");
		}
		vertex.put("name", vertexName);
		vertex.put("_id", vertexName);
		vertex.put("_type", "vertex");
		vertex.put("vertexType", "malware");
		vertex.put("source", "F-Secure");
		
		/////////////////////////////
		//parse the box at the top
		Element boxDiv = doc.select("div.box-rounded.br-blue").first().select("div.f-content").first();
		if(verboseDebug){
			System.out.println(boxDiv.html());
			System.out.println("=========");
		}
		Element aliasDiv = boxDiv.select("div").first().select("div").get(2);
		if(verboseDebug){
			System.out.println(aliasDiv.html());
			System.out.println("=========");
		}
		String[] aliasList = aliasDiv.text().split(" ");
		//TODO: how best to handle aliases in the long term?
		vertex.put("aliases", new JSONArray(aliasList));
		if(debug){
			System.out.println("Found " + aliasList.length + " items in aliasList:");
			for(int i=0; i<aliasList.length; i++){
				System.out.println(aliasList[i]);
			}
			System.out.println("=========");
		}
		
		//I think using divs as a table might actually be worse than using a table as divs...
		Element leftCatsDiv = boxDiv.select("div").first().select("div").get(3);
		if(verboseDebug){
			System.out.println(leftCatsDiv.html());
			System.out.println("=========");
		}
		String[] leftCatsList = leftCatsDiv.text().replace(":","").split(" ");
		if(debug){
			System.out.println("Found " + leftCatsList.length + " items in leftCatsList:");
			for(int i=0; i<leftCatsList.length; i++){
				System.out.println(leftCatsList[i]);
			}
			System.out.println("=========");
		}

		Element rightCatsDiv = boxDiv.select("div").first().select("div").get(4);
		if(verboseDebug){
			System.out.println(rightCatsDiv.html());
			System.out.println("=========");
		}
		String[] rightCatsList = rightCatsDiv.text().split(" ");
		if(debug){
			System.out.println("Found " + rightCatsList.length + " items in rightCatsList:");
			for(int i=0; i<rightCatsList.length; i++){
				System.out.println(rightCatsList[i]);
			}
			System.out.println("=========");
		}
		//make sure this is what you expected, then store fields.
		if(leftCatsList.length == 3 &&
			leftCatsList[0].equalsIgnoreCase("Category") && 
			leftCatsList[1].equalsIgnoreCase("Type") &&
			leftCatsList[2].equalsIgnoreCase("Platform"))
		{
			//keeping both fields as "malwareType", because they aren't used consistently
			JSONArray types = new JSONArray();
			types.put(rightCatsList[0]);
			types.put(rightCatsList[1]);
			vertex.put("malwareType", types);
			vertex.put("platform", rightCatsList[2]);
		}
		
		/////////////////////////
		//parse remaining page contents
		Element contentDiv = doc.select("div.content-protection").first().select("div.f-content").first();
		if(verboseDebug){
			System.out.println(contentDiv.html());
			System.out.println("=========");
		}
		Elements contents = contentDiv.children().first().children();
		Element curr, prev;
		removeBRs(contents);
		fixSectionHeaders(contents);
		if(verboseDebug){
			System.out.println(contents.outerHtml());
			System.out.println("=========");
		}
		//System.out.println("contents size is now: " + contents.size());
		for(int i = contents.size()-1; i>0; i--){
			curr = contents.get(i);
			prev = contents.get(i-1);
			//System.out.println(i + ":::" + prev.text() + ":::" + curr.text());
			//merge paragraphs, etc...
			if(curr.tagName().equals("p") && prev.tagName().equals("p")){
				prev.text( prev.text() + "\n" + curr.text() );
				contents.remove(i);
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("ul")){
				curr.text( ulToString(prev) + "\n" + curr.text() );
				contents.remove(i-1);
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("img")){
				//TODO
				curr.text( prev.attr("src") + "\n" + curr.text() );
				contents.remove(i-1);
				continue;
			}
			//pull out expected fields, based on headers...
			if(curr.tagName().equals("p") && prev.tagName().equals("h3") && prev.text().equals("Technical Details")){
				vertex.put("details", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i--;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h3") && prev.text().equals("Summary")){
				vertex.put("overview", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i--;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Automatic Disinfection")){
				String removalMessage = curr.text();
				if(removalMessage.startsWith("Allow F-Secure Anti-Virus to disinfect the relevant files.")){
					vertex.put("removal", "F-Secure");
				}else{
					vertex.put("removal", "F-Secure: " + removalMessage);
				}
				contents.remove(i);
				contents.remove(i-1);
				contents.remove(i-2);
				i -= 2;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Distribution")){
				vertex.put("distribution", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Behavior")){
				vertex.put("behavior", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
			}
		}
		
		
		
		if(debug){
			System.out.println("=====REMAINING:=====");
			System.out.println(contents.outerHtml());
			System.out.println("=========");
		}
	    
	    
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    return graph;
	}

	String ulToString(Element ul){
		String ret;
		ret = ul.text();
		System.out.println(":::ulToString is returning:::" + ret);
		return ret;
	}
}
