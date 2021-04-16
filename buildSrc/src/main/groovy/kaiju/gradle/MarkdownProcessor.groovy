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

import org.commonmark.node.*;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.*;
import org.commonmark.renderer.html.*;

/**
 * @author Ted Naleid
 * @author Andres Almiray
 */
class MarkdownProcessor {
    private String baseUri = null

    /**
     * Converts the provided Markdown into HTML
     *
     * <p>By default this method uses the shared configuration.  However, the default configuration can
     * be overridden by passing in a map or map-like object as the second argument.  With a custom
     * configuration, a new Pegdown processor is created <strong>every call to this method!</strong></p>
     *
     * @param text Markdown-formatted text
     * @return HTML-formatted text
     */
    String markdownToGhidraHtml(String text) {
        // lazily created, so we call the method directly
        Parser parser = Parser.builder().build();
        //HtmlRenderer renderer = HtmlRenderer.builder().build();
        HtmlRenderer renderer = HtmlRenderer.builder()
            .nodeRendererFactory(new HtmlNodeRendererFactory() {
                public NodeRenderer create(HtmlNodeRendererContext context) {
                    return new GhidraHtmlNodeRenderer(context);
                }
            })
            .build();
        Node document = parser.parse(text);
        
        renderer.render(document) // "<p>This is <em>Sparta</em></p>\n"
    }

}
