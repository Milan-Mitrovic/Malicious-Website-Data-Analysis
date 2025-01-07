#Author: Milan Mitrovic, s4663796

#Load malicious & benign website dataset 
df <- read.csv("C:/Datasets/malicious_and_benign_websites1.csv", header=TRUE,
                       sep = ',')

#Dimensions of dataset
dim(df)

#Identify duplicates
duplicates <- duplicated(df)
df[duplicates, ]

#Identify NULLS
colSums(is.na(df))

#Remove insignificant nulls in SERVER and DNS_QUERY_TIMES
df <- df[!is.na(df$SERVER) & !is.na(df$DNS_QUERY_TIMES), ]
#Verify removal
dim(df)

#Numeric summary for CONTENT_LENGTH
summary(df$CONTENT_LENGTH)

#Retrieve median from CONTENT_LENGTH
median_content_length <- median(df$CONTENT_LENGTH, na.rm = TRUE)
#Impute NULL values in CONTENT_LENGTH with median
df$CONTENT_LENGTH[is.na(df$CONTENT_LENGTH)] <- median_content_length
#Verify NULLS
colSums(is.na(df))

#Numeric summary for all numerical features
numerical_columns <- sapply(df, is.numeric)
summary(df[, numerical_columns])

#Get the value counts for any specific column
value_counts <- table(df$SERVER)
#Sort the value counts in descending order
sorted_value_counts <- sort(value_counts, decreasing = TRUE)
sorted_value_counts

#Standardizing CHARSET values
df$CHARSET <- ifelse(df$CHARSET == "utf-8", "UTF-8", df$CHARSET)
df$CHARSET <- ifelse(df$CHARSET == "iso-8859-1", "ISO-8859-1", df$CHARSET)
#Verify conversion
table(df$CHARSET)

#Standardizing WHOIS_COUNTRY values
df$WHOIS_COUNTRY <- ifelse(df$WHOIS_COUNTRY %in% c("United Kingdom", "[u'GB'; u'UK']"), "GB", df$WHOIS_COUNTRY)
df$WHOIS_COUNTRY <- ifelse(df$WHOIS_COUNTRY %in% c("us", "US"), "US", df$WHOIS_COUNTRY)
df$WHOIS_COUNTRY <- ifelse(df$WHOIS_COUNTRY %in% c("ru", "RU"), "RU", df$WHOIS_COUNTRY)
df$WHOIS_COUNTRY <- ifelse(df$WHOIS_COUNTRY == "se", "SE", df$WHOIS_COUNTRY)
df$WHOIS_COUNTRY <- ifelse(df$WHOIS_COUNTRY == "Cyprus", "CY", df$WHOIS_COUNTRY)
#Verify conversion
table(df$WHOIS_COUNTRY)


#Calculate the frequency of each value in the WHOIS_STATEPRO column
value_count <- table(df$WHOIS_STATEPRO)
#Identify values that are equal to 1 
values_to_remove <- names(value_count[value_count == 1])
#Remove == 1 rows in WHOIS_STATEPRO
df <- df[!df$WHOIS_STATEPRO %in% values_to_remove, ]
#Verify the removal
dim(df)  

#Standardizing WHOIS_STATEPRO
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("NY", "New York", "ny"), "NY", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("CA", "California", "ca"), "CA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("FL", "Florida", "FLORIDA"), "FL", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("TX", "Texas", "TEXAS"), "TX", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("VA", "Virginia", "va"), "VA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("DC", "Washington, DC"), "DC", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("WA", "Washington"), "WA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("AZ", "Arizona"), "AZ", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("NV", "Nevada"), "NV", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("UT", "UTAH", "Utah"), "UT", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("CO", "Colorado"), "CO", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("PA", "Pennsylvania"), "PA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("MA", "Massachusetts"), "MA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("IL", "Illinois"), "IL", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("MO", "Missouri"), "MO", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("NJ", "New Jersey"), "NJ", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("OH", "Ohio"), "OH", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("GA", "Georgia"), "GA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("MI", "Michigan"), "MI", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("KS", "Kansas"), "KS", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("LA", "Louisiana"), "LA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("OR", "Oregon"), "OR", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("NC", "North Carolina"), "NC", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("TN", "Tennessee"), "TN", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("WI", "Wisconsin"), "WI", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("MD", "Maryland"), "MD", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("MN", "Minnesota"), "MN", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("NM", "New Mexico"), "NM", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("AB", "ALBERTA"), "AB", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("BC", "British Columbia"), "BC", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("ON", "Ontario", "ONTARIO"), "ON", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("QC", "Quebec"), "QC", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("NSW", "New South Wales"), "NSW", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("QLD", "Queensland"), "QLD", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("ZH", "Zug", "Zhejiang"), "ZH", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("KG", "Krasnoyarsk"), "KYA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("P", "Porto"), "P", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("PANAMA", "Panama"), "PA", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("BJ", "beijingshi"), "BJ", df$WHOIS_STATEPRO)  
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("KY", "GRAND CAYMAN"), "KY", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("HN", "hunansheng"), "HN", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("LND", "London"), "LND", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("MVD", "Montevideo"), "MVD", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("NP", "New Providence"), "NP", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("B", "Barcelona"), "B", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("FK", "Fukuoka"), "FK", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("PR", "PRAHA", "Prague"), "PR", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("OS", "Osaka"), "OS", df$WHOIS_STATEPRO)
df$WHOIS_STATEPRO <- ifelse(df$WHOIS_STATEPRO %in% c("NH", "Noord-Holland"), "NH", df$WHOIS_STATEPRO)
#Remove junk values
df <- df[!(df$WHOIS_STATEPRO %in% c("--", "Not Applicable", "WC1N", "Austria" )), ]
#Verify conversion
table(df$WHOIS_STATEPRO)
dim(df)


#Load ggplot2 & RColorBrewer to configure plots
library(ggplot2)
library(RColorBrewer)

#Barplot for Type
ggplot(df, aes(x = factor(Type), fill = factor(Type))) +
  geom_bar(color = 'black') +
  geom_text(stat = 'count',
            aes(label = paste0(..count.., " (", round(..count.. / sum(..count..) * 100, 1), "%)")),
            vjust = -0.5,
            size = 3.5) +
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1", 
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  scale_x_discrete(labels = c("0" = "Benign", "1" = "Malicious")) +
  labs(title = "Website Type Distribution",
       x = "Type",
       y = "Count") +
  theme_classic() +
  theme(
    plot.title = element_text(size = 13, hjust = 0.6)
)

#Barplot for CHARSET vs Type
ggplot(df, aes(x = reorder(CHARSET, -table(CHARSET)[CHARSET]), fill = factor(Type))) +
  geom_bar(color = 'black', position = 'dodge') +  
  geom_text(stat = 'count',
            aes(label = ..count..),
            position = position_dodge(width = 0.9),
            vjust = -1.45,  
            size = 3) +
  geom_text(stat = 'count',
            aes(label = paste0("(", round(..count.. / sum(..count..) * 100, 1), "%)")),
            position = position_dodge(width = 0.9),
            vjust = -0.35,  
            size = 3) +
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  labs(title = "CHARSET vs Type",
       x = "Character Encoding",
       y = "Count") +
  theme_classic() +
  theme(
    plot.title = element_text(size = 13, hjust = 0.6),
    axis.text.x = element_text(angle = 0),
    axis.title.x = element_text(size = 10.5)  
  ) +
  scale_x_discrete(limits = levels(reorder(df$CHARSET, -table(df$CHARSET)[df$CHARSET]))[1:3])

#Barplot for SERVER vs Type
ggplot(df, aes(x = reorder(SERVER, -table(SERVER)[SERVER]), fill = factor(Type))) +
  geom_bar(color = 'black', position = 'dodge') +  
  geom_text(stat = 'count',
            aes(label = ..count..),
            position = position_dodge(width = 0.9),
            vjust = -1.50,  
            size = 2.5) +
  geom_text(stat = 'count',
            aes(label = paste0("(", round(..count.. / sum(..count..) * 100, 1), "%)")),
            position = position_dodge(width = 0.9),
            vjust = -0.35,  
            size = 2.5) +
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  labs(title = "SERVER vs Type",
       x = "Server",
       y = "Count") +
  theme_classic() +
  theme(
    plot.title = element_text(size = 13, hjust = 0.6),
    axis.text.x = element_text(angle = 45, hjust = 1, size = 10), # Adjust angle for readability
    axis.title.x = element_text(size = 11)  
  ) +
  scale_x_discrete(limits = names(sort(table(df$SERVER), decreasing = TRUE))[1:5])

#Barplot for WHOIS_COUNTRY vs Type
ggplot(df, aes(x = reorder(WHOIS_COUNTRY, -table(WHOIS_COUNTRY)[WHOIS_COUNTRY]), fill = factor(Type))) +
  geom_bar(color = 'black', position = 'dodge') +  
  geom_text(stat = 'count',
            aes(label = ..count..),
            position = position_dodge(width = 0.9),
            vjust = -1.45,  
            size = 3) +
  geom_text(stat = 'count',
            aes(label = paste0("(", round(..count.. / sum(..count..) * 100, 1), "%)")),
            position = position_dodge(width = 0.9),
            vjust = -0.35,  
            size = 3) +
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  labs(title = "WHOIS_COUNTRY vs Type",
       x = "Country",
       y = "Count") +
  theme_classic() +
  theme(
    plot.title = element_text(size = 13, hjust = 0.6),
    axis.text.x = element_text(angle = 0), # Adjust angle for readability
    axis.title.x = element_text(size = 11)  
  ) +
  scale_x_discrete(limits = names(sort(table(df$WHOIS_COUNTRY), decreasing = TRUE))[1:5])

#Barplot for WHOIS_STATEPRO vs Type
ggplot(df, aes(x = reorder(WHOIS_STATEPRO, -table(WHOIS_STATEPRO)[WHOIS_STATEPRO]), fill = factor(Type))) +
  geom_bar(color = 'black', position = 'dodge') +  
  geom_text(stat = 'count',
            aes(label = ..count..),
            position = position_dodge(width = 0.9),
            vjust = -1.45,  
            size = 3) +
  geom_text(stat = 'count',
            aes(label = paste0("(", round(..count.. / sum(..count..) * 100, 1), "%)")),
            position = position_dodge(width = 0.9),
            vjust = -0.35,  
            size = 2.5) +
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  labs(title = "WHOIS_STATEPRO vs Type",
       x = "State/Province",
       y = "Count") +
  theme_classic() +
  theme(
    plot.title = element_text(size = 12, hjust = 0.6),
    axis.text.x = element_text(angle = 0), # Adjust angle for readability
    axis.title.x = element_text(size = 10.5)  
  ) +
  scale_x_discrete(limits = names(sort(table(df$WHOIS_STATEPRO), decreasing = TRUE))[1:7])

#KDE Plot for URL_LENGTH vs Type
ggplot(df, aes(x = URL_LENGTH, fill = factor(Type), color = factor(Type))) +
  geom_density(alpha = 0.5, size = 1) + 
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  scale_color_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  labs(title = "URL_LENGTH vs Type",
       x = "URL Length",
       y = "Density") +
  theme_classic() +
  theme(
    plot.title = element_text(size = 13, hjust = 0.6),
    axis.title.x = element_text(size = 10.5),
    axis.title.y = element_text(size = 10.5),
    legend.title = element_text(size = 10),
    legend.text = element_text(size = 9)
  )

#KDE Plot for NUMBER_SPECIAL_CHARACTERS vs Type
ggplot(df, aes(x = NUMBER_SPECIAL_CHARACTERS, fill = factor(Type), color = factor(Type))) +
  geom_density(alpha = 0.5, size = 1) + 
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  scale_color_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  labs(title = "NO_SPECIAL_CHARACTERS vs Type",
       x = "Special Characters",
       y = "Density") +
  theme_classic() +
  theme(
    plot.title = element_text(size = 13, hjust = 0.6),
    axis.title.x = element_text(size = 10.5),
    axis.title.y = element_text(size = 10.5),
    legend.title = element_text(size = 10),
    legend.text = element_text(size = 9)
  )


#KDE Plot for CONTENT_LENGTH vs Type
ggplot(df, aes(x = CONTENT_LENGTH, fill = factor(Type), color = factor(Type))) +
  geom_density(alpha = 0.5, size = 1) + 
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  scale_color_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  labs(title = "CONTENT_LENGTH vs Type",
       x = "Content Length",
       y = "Density") +
  scale_x_continuous(labels = scales::comma) +  # Convert x-axis labels to comma format
  scale_y_continuous(labels = scales::comma) +  # Convert y-axis labels to comma format
  theme_classic() +
  theme(
    plot.title = element_text(size = 13, hjust = 0.6),
    axis.title.x = element_text(size = 10.5),
    axis.title.y = element_text(size = 10.5),
    legend.title = element_text(size = 10),
    legend.text = element_text(size = 9)
  )


#KDE Plot for TCP_CONVERSATION_EXCHANGE vs Type
ggplot(df, aes(x = TCP_CONVERSATION_EXCHANGE, fill = factor(Type), color = factor(Type))) +
  geom_density(alpha = 0.5, size = 1) + 
  scale_fill_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  scale_color_brewer(
    name = "Type",
    palette = "Pastel1",  
    labels = c("0" = "Benign", "1" = "Malicious")
  ) +
  labs(title = "TCP_CONVERSATION_EXCHANGE vs Type",
       x = "TCP Packets",
       y = "Density") +
  theme_classic() +
  theme(
    plot.title = element_text(size = 13, hjust = 0.6),
    axis.title.x = element_text(size = 10.5),
    axis.title.y = element_text(size = 10.5),
    legend.title = element_text(size = 10),
    legend.text = element_text(size = 9)
  )


#Feature selection
df <- df[, !(names(df) %in% c("URL", "WHOIS_REGDATE", "WHOIS_UPDATED_DATE"))]
dim(df) #Verify removal 

#Convert target variable Type to factor
df$Type <- factor(df$Type)
#Load caret
library("caret")

#Encode categorical features
dummy_model <- dummyVars(~ CHARSET + SERVER + WHOIS_COUNTRY
                         + WHOIS_STATEPRO, data = df)

#Apply dummyVars to df
df_encoded <- predict(dummy_model, newdata = df)

#Convert result to df
df_encoded <- data.frame(df_encoded)

#Combine encoded df with original df
df_combined <- cbind(df_encoded, df[, !names(df) %in% c("CHARSET",
                        "SERVER", "WHOIS_COUNTRY", "WHOIS_STATEPRO")])
#Verify encoding
dim(df_combined)

#Split dataset randomly into train/test with 7:3 ratio
set.seed(42)
train_index <- sample(1:nrow(df_combined), 0.7 * nrow(df_combined))
train <- df_combined[train_index, ]
test <- df_combined[-train_index, ]

#Feature-splitting
X_train <- train[, !names(train) %in% "Type"]  
y_train <- train$Type 

#Train the Decision Tree model
model_dt <- train(X_train,                  
                  y_train,                   
                  method = "rpart",           
                  trControl = trainControl(method = "cv", number = 5), 
                  tuneLength = 5)  
model_dt



#Train the KNN model 
model_knn <- train(X_train,                  
                  y_train,                   
                  method = "knn", 
                  preProcess = c("center"),
                  trControl = trainControl(method = "cv", number = 5),  
                  tuneLength = 5)     
model_knn 


#Train the Random Forest model 
model_rf <- train(X_train,                  
                  y_train,                   
                  method = "rf",             
                  trControl = trainControl(method = "cv", number = 5),  
                  tuneLength = 5)     
model_rf 

#Feature-splitting
X_test <- test[, !names(train) %in% "Type"]  
y_test <- test$Type

#Prediction on the test set
pred_y_test_dt <- predict(model_dt, newdata = X_test)
pred_y_test_knn <- predict(model_knn, newdata = X_test)
pred_y_test_rf <- predict(model_rf, newdata = X_test)

#Evaluation/confusion matrix 
cm_dt <- confusionMatrix(pred_y_test_dt, y_test)
print(cm_dt)
cm_knn <- confusionMatrix(pred_y_test_knn, y_test)
print(cm_knn)
cm_rf <- confusionMatrix(pred_y_test_rf, y_test)
print(cm_rf)
