/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2013-2020 Andres Almiray.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package kaiju.gradle

import java.util.HashMap

import org.commonmark.node.*;
import org.commonmark.renderer.*;
import org.commonmark.renderer.html.*;

public class GhidraHtmlNodeRenderer extends CoreHtmlNodeRenderer implements NodeRenderer {

    //protected final HtmlNodeRendererContext context;
    private final HtmlWriter html;

    public GhidraHtmlNodeRenderer(HtmlNodeRendererContext context) {
        super(context);
        this.html = context.getWriter();
    }

    @Override
    public void visit(Document document) {
        html.tag("html");
        html.line();
        html.tag("head");
        html.line();
        html.tag("title");
        html.text("Kaiju Documentation");
        html.tag("/title");
        html.line();
        // <LINK rel="stylesheet" type="text/css" href="../../shared/Frontpage.css">
        HashMap<String,String> linkattrs = new HashMap<>();
        linkattrs.put("rel","stylesheet");
        linkattrs.put("type","text/css");
        linkattrs.put("href","../../shared/Frontpage.css");
        html.tag("link", linkattrs);
        html.line();
        html.tag("/head");
        html.line();
        html.line();
        // render rest of the document
        visitChildren(document);
        html.tag("/html");
    }
    
    // based on code from CommonMark implementation
    @Override
    public void visit(Image image) {
        String url = image.getDestination();

        AltTextVisitor altTextVisitor = new AltTextVisitor();
        image.accept(altTextVisitor);
        String altText = altTextVisitor.getAltText();

        Map<String, String> attrs = new LinkedHashMap<>();
        if (context.shouldSanitizeUrls()) {
            url = context.urlSanitizer().sanitizeImageUrl(url);
        }

        attrs.put("src", context.encodeUrl(url));
        attrs.put("alt", altText);
        if (image.getTitle() != null) {
            attrs.put("title", image.getTitle());
        }
        
        // Ghidra specific default
        attrs.put("border", "1");

        Map<String, String> pattrs = new LinkedHashMap<>();
        pattrs.put("align","center");
        
        html.tag("p", pattrs);
        html.tag("img", getAttrs(image, "img", attrs), true);
        html.tag("/p");
        
        // use the alttext as an image caption
        pattrs.put("style","font-style: italic;");
        html.tag("p", pattrs);
        html.text(altText);
        html.tag("/p");
    }
    
    // below this line: boilerplate from CommonMark
    
    private Map<String, String> getAttrs(Node node, String tagName) {
        return getAttrs(node, tagName, Collections.<String, String>emptyMap());
    }

    private Map<String, String> getAttrs(Node node, String tagName, Map<String, String> defaultAttributes) {
        return context.extendAttributes(node, tagName, defaultAttributes);
    }

    private static class AltTextVisitor extends AbstractVisitor {

        private final StringBuilder sb = new StringBuilder();

        String getAltText() {
            return sb.toString();
        }

        @Override
        public void visit(Text text) {
            sb.append(text.getLiteral());
        }

        @Override
        public void visit(SoftLineBreak softLineBreak) {
            sb.append('\n');
        }

        @Override
        public void visit(HardLineBreak hardLineBreak) {
            sb.append('\n');
        }
    }

}
