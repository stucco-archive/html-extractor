package HTMLExtractor;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.*;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
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
	
	protected static void removeBRs(Elements contents){
		Element curr;
		for(int i = contents.size()-1; i>=0; i--){
			curr = contents.get(i);
			if(curr.tagName().equals("br")){
				contents.remove(i);
				continue;
			}
		}
	}
	
	//NB: assumes dt and dd are one-to-one (will skip ones that aren't)
	//NB: also assumes that dt and dd tags have text()-able content.
	protected Map<String, String> dlToMap(Element dl) {
		HashMap<String, String> retMap = new HashMap<String, String>();
		if( dl.tagName().equals("dl") ){
			Elements terms = dl.getElementsByTag("dt");
			Element currTerm, currDef;
			for(int i=0; i<terms.size(); i++){
				currTerm = terms.get(i);
				currDef = currTerm.nextElementSibling();
				if(currDef != null && currDef.tagName().equals("dd")){
					retMap.put(currTerm.text(), currDef.text());
				}
			}
			return retMap;	
		}
		else return null;
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
	
}
