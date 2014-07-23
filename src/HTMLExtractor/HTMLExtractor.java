package HTMLExtractor;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.regex.*;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public abstract class HTMLExtractor {

	protected static String findWithRegex(String content, String regex){
		return findWithRegex(content, regex, 1);
	}
	
	protected static String findWithRegex(String content, String regex, int groupNum){
		Pattern pattern = Pattern.compile(regex);
	    Matcher matcher = pattern.matcher(content);
	    matcher.find();
		return matcher.group(1);
	}

	protected static void trimAll(String[] items) {
		for(int i=0; i<items.length; i++){
	    	items[i] = items[i].trim();
	    }
	}
	
	protected long convertTimestamp(String time, String format)	{ 
		Date date = new Date();
		try {
			SimpleDateFormat df = new SimpleDateFormat(format);
  			date = df.parse(time);
  			return date.getTime();	

		} catch	(ParseException e)	{
			e.printStackTrace();
		}
  		return date.getTime();	
	}
	
	protected ArrayList<String> findAllLinkHrefs(Element content) {
		Elements refs = content.select("a[href]");
		ArrayList<String> hrefStrings = new ArrayList<String>();
		String hrefString = "";
		for(int i=0; i<refs.size(); i++){
			hrefString = refs.get(i).attr("href");
			hrefStrings.add(hrefString);
		}
		//System.out.println(refs);
		//System.out.println(refStrings);
		return hrefStrings;
	}
	
	public static void main(String[] args) throws IOException {
		
		Charset charset = Charset.defaultCharset();
		int entryNum = 2222;
		boolean localMode = true;
		String info, discussion, exploit, solution, references;
		
		if(localMode){
			File infoFD = new File("./"+entryNum+".info.html");
			info = FileUtils.readFileToString(infoFD, charset);
			
			File discussionFD = new File("./"+entryNum+".discussion.html");
			discussion = FileUtils.readFileToString(discussionFD, charset);
			
			File exploitFD = new File("./"+entryNum+".exploit.html");
			exploit = FileUtils.readFileToString(exploitFD, charset);
			
			File solutionFD = new File("./"+entryNum+".solution.html");
			solution = FileUtils.readFileToString(solutionFD, charset);
			
			File referencesFD = new File("./"+entryNum+".references.html");
			references = FileUtils.readFileToString(referencesFD, charset);
		}
		else{
			URL u;
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/info");
			info = IOUtils.toString(u);
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/discussion");
			discussion = IOUtils.toString(u);
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/exploit");
			exploit = IOUtils.toString(u);
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/solution");
			solution = IOUtils.toString(u);
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/references");
			references = IOUtils.toString(u);
		}
		
		BugtraqExtractor bugtraqExt = new BugtraqExtractor(info, discussion, exploit, solution, references);
		JSONObject vertex = bugtraqExt.getGraph();
	    
	    System.out.println(vertex.toString(2));

	}
}
