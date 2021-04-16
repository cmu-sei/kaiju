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

/**
 * @author Andres Almiray
 */
enum Conversion {
    MARKDOWN('markdownToGhidraHtml', [MD_EXTENSION, MARKDOWN_EXTENSION], HTML_EXTENSION)

    private static final String MD_EXTENSION = '.md'
    private static final String HTML_EXTENSION = '.html'
    private static final String MARKDOWN_EXTENSION = '.markdown'

    private final String methodName
    private final List<String> extensions = []
    private final String targetExtension
    private final MarkdownProcessor processor = new MarkdownProcessor()

    Conversion(String methodName, List<String> extensions, String targetExtension) {
        this.methodName = methodName
        this.extensions.addAll(extensions)
        this.targetExtension = targetExtension
    }

    boolean accept(File file) {
        for (String ext : extensions) {
            if (file.name.endsWith(ext)) return true
        }
        false
    }

    @SuppressWarnings('ConfusingMethodName')
    String targetExtension() {
        targetExtension
    }

    @SuppressWarnings('ConfusingMethodName')
    List<String> extensions() {
        extensions
    }

    String convert(String input, Map configuration) {
        processor."$methodName"(input)
    }

    /**
     * Strip the filename extension from the given path,
     * e.g. "mypath/myfile.txt" -> "mypath/myfile".
     *
     * @param path the file path (may be <code>null</code>)
     * @return the path with stripped filename extension,
     *         or <code>null</code> if none
     */
    static String stripFilenameExtension(String path) {
        if (path == null) {
            return null
        }
        int extIndex = path.lastIndexOf('.')
        if (extIndex == -1) {
            return path
        }
        int folderIndex = path.lastIndexOf('/')
        if (folderIndex > extIndex) {
            return path
        }
        path[0..<extIndex]
    }
}
