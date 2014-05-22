/*
 * Copyright (c) 2008-2012 Tomas Varaneckas
 * http://www.varaneckas.com
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
package com.googlecode.gmail4j.util;

/**
 * Common constants used for internel development.
 * <p>
 * Example use:
 * <p><blockquote><pre>
 *     store.getFolder(Constants.GMAIL_INBOX);
 * </pre></blockquote>
 *
 * @author Rajiv Perera &lt;rajivderas@gmail.com&gt;
 * @since 0.4
 */
public class Constants {

    public static final String GMAIL_EXTENSION = "@gmail.com";
    // used for messsage header information extraction tags
    public static final String MESSAGE_ID = "MESSAGE-ID";
    public static final String MESSAGE_SUBJECT = "SUBJECT";
    public static final String MESSAGE_IN_REPLY_TO = "IN-REPLY-TO";
    public static final String MESSAGE_REFERENCES = "REFERENCES";
    public static final int PREVIEW_LENGTH = 80;
}
