# Use Node.js 20 as the base image
FROM node:20-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json to the container
COPY package*.json ./

# Install project dependencies
RUN npm install

# Install PM2 globally
RUN npm install pm2 -g 

# Copy the rest of the application files 
COPY . . 

# Expose the port the app runs on 
EXPOSE 4600

# Run the application using PM2 with ecosystem file 
CMD ["pm2-runtime", "start", "ecosystem.config.js"]
